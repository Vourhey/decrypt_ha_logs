import json
import logging
import os
import sys
import urllib.parse
from pathlib import Path
from zipfile import ZipFile

import ipfs_api
import requests
import yaml
from ipfs_remote.ipfshttpclient2.exceptions import ConnectionError
from nacl.secret import SecretBox
from requests.adapters import HTTPAdapter
from robonomicsinterface import Account, Datalog
from substrateinterface import Keypair, KeypairType
from urllib3.util import Retry

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

CREDS_FILE = "creds.yaml"
ARCHIVE_FILES_DIR = "encrypted_logs"
NETWORK_WSS = "wss://polkadot.rpc.robonomics.network/"
PINATA_GATEWAY = "https://ipfs.io"


def ipfs_download(cid: str, file_path: str, gateway: str) -> None:
    """
    Function for download files from IPFS
    :param cid: File CID
    :param file_path: Full path for saving file
    :param gateway: IPFS gateway to download file
    :return: None
    """
    if gateway:
        url: str = urllib.parse.urljoin(gateway, "ipfs/" + cid)
        retry_num: int = 5
        try:
            # Define the retry strategy
            retry_strategy = Retry(
                total=retry_num,
                backoff_factor=3,
                status_forcelist=[429, 500, 502, 503, 504],
            )

            # Create an HTTP adapter with the retry strategy and mount it to session
            adapter = HTTPAdapter(max_retries=retry_strategy)

            # Create a new session object
            session = requests.Session()
            session.mount("http://", adapter)
            session.mount("https://", adapter)

            response = session.get(url, allow_redirects=True)

            open(file_path, "wb").write(response.content)

            return

        except Exception as e:
            print("Error %s", e)
    ipfs_api.download(cid, file_path)
    return


def parse_decrypted(text: str) -> tuple[str, dict | None]:
    """
    Parse decrypted data if metadata was added or return just data overwise
    """
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "payload" in obj:
            return obj["payload"], obj.get("meta")
    except json.JSONDecodeError:
        pass
    return text, None


def clean_archive_dir(path: str) -> None:
    for entry in os.scandir(path):
        if entry.is_file():
            os.remove(entry.path)


def decrypt_msg(
    encrypted_msg: str,
    sender_public_key: bytes,
    recipient_keypair: Keypair,
) -> bytes:
    """
    Decrypt message with recepient private key and sender puplic key

    :param encrypted_msg:       Message to decrypt
    :param sender_public_key:   Sender public key
    :param recipient_keypair:   Recepient account keypair

    :return: Decrypted message
    """
    if encrypted_msg[:2] == "0x":
        encrypted_msg = encrypted_msg[2:]

    bytes_encrypted = bytes.fromhex(encrypted_msg)

    return recipient_keypair.decrypt_message(bytes_encrypted, sender_public_key)


def multi_envelope_decrypt_data(
    encryption_package: str,
    recipient_account: Account,
    sender_address: str,
) -> str:
    """
    Decrypt JSON structure with encrypted data: first decrypt the secret key
    (asymmetric), then use the secret key to decrypt the data itself.

    :return: data after decryption
    """

    # Check if JSON encryption package is valid
    try:
        package_json = json.loads(encryption_package)
    except json.JSONDecodeError as e:
        LOGGER.warning("Envelope decrypt: invalid JSON package")
        raise ValueError("Invalid encryption package JSON") from e

    try:
        encrypted_secret_keys = package_json["keys"]
        encrypted_data_hex = package_json["data"]
    except (TypeError, ValueError) as e:
        LOGGER.warning("Envelope decrypt: missing required fields in package")
        raise ValueError("Invalid encryption package structure") from e

    # Check if recipient address is authorized with secret key
    recipient_address = recipient_account.get_address()
    encrypted_secret_key = encrypted_secret_keys.get(recipient_address)
    if not encrypted_secret_key:
        LOGGER.warning(
            "Envelope decrypt: recipient key not found for %s", recipient_address
        )
        raise ValueError("Recipient is not authorized for this package")

    # Get secret key from public-key decryption

    try:
        sender_kp = Keypair(
            ss58_address=sender_address, crypto_type=KeypairType.ED25519
        )

        secret_key = decrypt_msg(
            encrypted_secret_key, sender_kp.public_key, recipient_account.keypair
        )
    except Exception as e:
        LOGGER.warning("Envelope decrypt: failed to unwrap secret key")
        raise ValueError("Failed to decrypt secret key") from e

    try:
        # Deserialize encrypted data: remove 0x from beginning,
        # transform to bytes
        encrypted_data = bytes.fromhex(encrypted_data_hex[2:])

        # Decrypt actual message (in form of bytes) and decode it
        decrypted_data_bytes = SecretBox(secret_key).decrypt(encrypted_data)
        decrypted_data = decrypted_data_bytes.decode("utf-8")

        return decrypted_data
    except Exception as e:
        LOGGER.warning("Envelope decrypt: failed to decrypt payload")
        raise ValueError("Failed to decrypt payload") from e


creds_path = Path(CREDS_FILE)
with open(creds_path, "r") as f:
    creds_dict: dict = yaml.load(f, Loader=yaml.SafeLoader)

recipient_seed: str = creds_dict.get("recipient_seed")
recipient_account = Account(
    recipient_seed, crypto_type=KeypairType.ED25519, remote_ws=NETWORK_WSS
)
sender_address: str = creds_dict.get("sender_address")


datalog = Datalog(recipient_account, rws_sub_owner=recipient_account.get_address())

[timestamp, datalog_content] = datalog.get_item(addr=sender_address, index=16)

archive_name = str(datalog_content)

cid = archive_name
archive_path = os.path.join(os.path.curdir, archive_name)
archive_files_path = os.path.join(os.path.curdir, ARCHIVE_FILES_DIR)
clean_archive_dir(archive_files_path)

print(cid)

try:
    ipfs_download(cid, archive_path, PINATA_GATEWAY)
except ConnectionError:
    LOGGER.error("Please, run IPFS daemon or check your Internet connection")
    sys.exit()

with ZipFile(archive_path, "r") as zip_file:
    zip_file.extractall(archive_files_path)

for entry in os.scandir(archive_files_path):
    with open(entry.path, "r", encoding="utf-8") as f:
        data = f.read()

    try:
        decrypted_data = multi_envelope_decrypt_data(
            data, recipient_account, sender_address
        )

        decrypted_payload, decrypted_meta = parse_decrypted(decrypted_data)

        file_name = decrypted_meta.get("orig_file_name")

        file_path = os.path.join(os.path.curdir, file_name)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(decrypted_payload)
            LOGGER.info("File %s is successfully decrypted", file_path)
    except Exception as e:
        LOGGER.warning("Problem during decrypting files: %s", e)

os.remove(archive_path)
clean_archive_dir(archive_files_path)
LOGGER.info("All done")
