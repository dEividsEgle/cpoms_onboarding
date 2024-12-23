import os
import logging
import io
import smtplib
import pyotp
import re
import imaplib
import email
from pathlib import Path
from email.message import EmailMessage
from dotenv import load_dotenv
from datetime import datetime
from idlelib.debugger_r import debugging
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver import ActionChains
from selenium.webdriver.edge.options import Options
from selenium.webdriver.edge.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

debugging = False

log_stream = io.StringIO()
log_format = "%(message)s"

load_dotenv()

LOGIN_PAGE = os.getenv("LOGIN_PAGE")
ACCOUNT_EMAIL = os.getenv("ACCOUNT_EMAIL")
ACCOUNT_PASSWORD = os.getenv("ACCOUNT_PASSWORD")
MFA_SECRET = os.getenv("MFA_SECRET")
USER_PAGE = os.getenv("USER_PAGE")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL")
PROCESSED_UIDS_FILE = os.getenv("PROCESSED_UIDS_FILE")
EMAIL_SERVER = os.getenv("EMAIL_SERVER")
EMAIL_PORT = int(os.getenv("EMAIL_PORT"))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_SUBJECT = os.getenv("EMAIL_SUBJECT")
LOG_DIR = os.getenv("LOG_DIR")

script_directory = Path(__file__).resolve().parent
script_name = Path(__file__).name
driver_path = script_directory.joinpath("edgedriver_macarm64", "msedgedriver")

edge_options = Options()
if debugging:
    edge_options.add_experimental_option("detach", True)
else:
    edge_options.add_argument("--headless")

log_format = "%(asctime)s - %(levelname)s - %(message)s"
log_time_format = "%H:%M:%S"

log_dir = Path(LOG_DIR)
log_dir.mkdir(parents=True, exist_ok=True)
log_file = log_dir / f"{Path(script_name).stem}_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
absolute_log_path = log_file.resolve()

handlers = [
    logging.FileHandler(log_file),
    logging.StreamHandler()
]

if debugging:
    handlers.append(logging.StreamHandler(stream=log_stream))

logging.basicConfig(level=logging.INFO, format=log_format, datefmt=log_time_format, handlers=handlers)

def wait_for_element(driver, by, element_identifier, timeout=10):
    try:
        element_present = EC.presence_of_element_located((by, element_identifier))
        WebDriverWait(driver, timeout).until(element_present)
    except TimeoutException:
        logging.info(f"Time out waiting for {element_identifier}")
        return None
    return driver.find_element(by, element_identifier)

def generate_totp(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()

def get_processed_uids():
    if not os.path.exists(PROCESSED_UIDS_FILE):
        return set()
    with open(PROCESSED_UIDS_FILE, "r") as file:
        return set(line.strip() for line in file)

def save_processed_uids(uid):
    with open(PROCESSED_UIDS_FILE, "a") as file:
        file.write(f"{uid}\n")

def fetch_latest_email():
    try:
        mail = imaplib.IMAP4_SSL(EMAIL_SERVER, EMAIL_PORT)
        mail.login(EMAIL_USER, EMAIL_PASSWORD)
        mail.select("inbox")
        logging.info(f"Successfully Authenticated: Checking for mail in {EMAIL_USER} inbox.")
        logging.info(f"Email Subject: {EMAIL_SUBJECT}")

        status, messages = mail.search(None, f'(SUBJECT "{EMAIL_SUBJECT}")')
        if status != "OK":
            logging.info("No emails found with the specified subject.")
            return ""

        email_ids = messages[0].split()
        if not email_ids:
            logging.info("No matching emails found.")
            return ""

        processed_uids = get_processed_uids()

        for email_id in reversed(email_ids):
            status, response = mail.fetch(email_id, "(UID)")
            uid = response[0].split()[-1].decode()

            if uid in processed_uids:
                logging.info(f"Email with UID {uid} already processed. Skipping.")
                continue


            status, msg_data = mail.fetch(email_id, "(RFC822)")
            if status != "OK" or not msg_data or not isinstance(msg_data[0], tuple):
                logging.info(f"Failed to fetch email with UID {uid}.")
                continue

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)
            save_processed_uids(uid)
            mail.logout()

            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        return part.get_payload(decode=True).decode()
            else:
                return msg.get_payload(decode=True).decode()

    except Exception as e:
        logging.info(f"Error fetching email: {e}")
        return ""

def parse_users_from_email():
    users = []
    email_content = fetch_latest_email()
    if not email_content:
        logging.info("No email content to parse.")
        return users

    user_pattern = re.compile(
        r"(?P<first_name>\w+),\s*(?P<last_name>[\w'-]+),.*?,.*?,(?P<email>[\w.-]+@[\w.-]+\.\w+)"
    )
    matches = user_pattern.finditer(email_content)
    for match in matches:
        full_name = f"{match.group('first_name')} {match.group('last_name')}"
        user_email = match.group('email')
        users.append({
            "name": full_name,
            "email": user_email,
        })
    return users

def login_to_account(driver):
    driver.get(LOGIN_PAGE)

    username_input = wait_for_element(driver, By.ID, "Username")
    if username_input:
        username_input.send_keys(ACCOUNT_EMAIL)
    next_button = wait_for_element(
        driver, By.XPATH, '//button[contains(@class, "btn-primary") and contains(., "Next")]'
    )
    if next_button:
        next_button.click()

    password_input = wait_for_element(driver, By.ID, "Password")
    if password_input:
        password_input.send_keys(ACCOUNT_PASSWORD)
    login_button = wait_for_element(
        driver, By.XPATH, '//span[contains(@class, "ladda-label") and text()="Log In"]/ancestor::button'
    )
    if login_button:
        login_button.click()

    mfa_input = wait_for_element(driver, By.ID, "code")
    if mfa_input:
        mfa_code = generate_totp(MFA_SECRET)
        print(f"Generated MFA Code: {mfa_code}")
        mfa_input.send_keys(mfa_code)
    authenticate_button = wait_for_element(
        driver, By.XPATH, '//button[@name="auth" and @type="submit" and contains(@class, "btn-primary")]'
    )
    if authenticate_button:
        authenticate_button.click()

def navigate_to_user_page(driver):
    driver.get(USER_PAGE)

def process_user(driver, target_name):
    try:
        user_links = driver.find_elements(
            By.XPATH, '//a[contains(@class, "dormant-user")]'
        )

        if not user_links:
            return False

        for link in user_links:
            user_name = link.text.strip()
            if user_name == target_name:
                link.click()
                return True

        logging.info(f"User '{target_name}' not found.")
        return False

    except Exception as e:
        logging.info(f"Error processing user: {e}")

def set_email_and_group(driver, email_address):
    try:
        email_input = wait_for_element(driver, By.ID, "user_email")

        if email_input:
            if email_input.get_dom_attribute("value") == email_address:
                logging.info(f"Email '{email_address}' is already set.")
            else:
                email_input.clear()
                email_input.send_keys(email_address)
                logging.info(f"Entered email: {email_address}")
        else:
            logging.info("Email input not found.")
            return False

        group_dropdown_trigger = wait_for_element(driver, By.CLASS_NAME, "select2-choice")
        if group_dropdown_trigger:
            ActionChains(driver).move_to_element(group_dropdown_trigger).click().perform()
        else:
            logging.info("User group dropdown trigger not found.")
            return False

        WebDriverWait(driver, 10).until(
            EC.visibility_of_element_located((By.CLASS_NAME, "select2-results"))
        )

        all_options = driver.find_elements(By.CLASS_NAME, "select2-result-label")
        if not all_options:
            logging.info("No dropdown options found.")
            return False

        all_staff_option = None
        for option in all_options:
            if option.text.strip() == "All Staff":
                all_staff_option = option
                break

        if all_staff_option:
            all_staff_option.click()
            logging.info("User group set to 'All Staff'.")
        else:
            logging.info("'All Staff' option not found in dropdown.")
            return False

        return True

    except Exception as e:
        logging.error(f"Error in set_email_and_group: {e}")
        if "Email address has already been taken" in str(e):
            logging.info(f"Email '{email_address}' is already associated with another user.")
        return False

def create_user(driver):
    try:
        submit_button = wait_for_element(driver, By.NAME, "commit")
        if submit_button:
            submit_button.click()

        try:
            WebDriverWait(driver, 5).until(
                EC.presence_of_element_located((By.ID, "errorExplanation"))
            )
            error_element = driver.find_element(By.ID, "errorExplanation")
            error_message = error_element.text

            if "Email address has already been taken" in error_message:
                logging.info(f"Error: {error_message}. Returning to user page.")
                navigate_to_user_page(driver)
                return False
            else:
                logging.info(f"Unexpected error during user creation: {error_message}.")
                return False

        except TimeoutException:
            try:
                success_notice = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "p.notice"))
                )
                if "User was successfully created." in success_notice.text:
                    logging.info("User creation confirmed: 'User was successfully created.' notice found.")
                    return True
            except TimeoutException:
                logging.info("User creation failed: Neither error nor success notice was found.")
                return False

    except Exception as e:
        logging.error(f"Error during user creation: {e}")
        return False

def send_summary_email(successful_users, failed_users):
    msg = EmailMessage()
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL
    msg['Subject'] = "Staff Onboarding - CPOMS User Activation Summary"
    msg.set_content(log_stream.getvalue())
    content = "Task Summary:\n\n"

    if successful_users:
        content += "Successfully Processed Users:\n" + "\n".join(successful_users) + "\n\n"
    else:
        content += "No users were successfully processed.\n\n"
    if failed_users:
        content += "Failed Users:\n" + "\n".join(failed_users) + "\n"
    else:
        content += "No failures occurred.\n"

    msg.set_content(content)
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(SENDER_EMAIL, SENDER_PASSWORD)
            smtp.send_message(msg)
    except Exception as e:
        logging.error(f"Failed to send summary email: {e}")

def main():
    service = Service(str(driver_path))
    driver = webdriver.Edge(service=service, options=edge_options)

    try:
        login_to_account(driver)
        navigate_to_user_page(driver)

        users = parse_users_from_email()
        if not users:
            logging.info("No users found in the email.")
            return

        successful_users = []
        failed_users = []

        for user in users:
            target_name = user["name"]
            email_address = user["email"]

            logging.info(f"Processing user {target_name} with email {email_address}...")

            try:
                user_found = process_user(driver, target_name)
                if user_found:
                    logging.info(f"User {target_name} found, attempting to set email and group.")
                    email_and_group_updated = set_email_and_group(driver, email_address)

                    if email_and_group_updated:
                        logging.info(f"Email and user group updated successfully for {target_name}.")
                        user_created = create_user(driver)

                        if user_created:
                            logging.info(f"User {target_name} created successfully.")
                            successful_users.append(f"{target_name} ({email_address})")
                        else:
                            logging.info(f"Failed to create user {target_name}.")
                            failed_users.append(f"{target_name} ({email_address}): User creation failed.")
                    else:
                        logging.info(f"Failed to update email or group for {target_name}.")
                        failed_users.append(f"{target_name} ({email_address}): Email/group update failed.")
                else:
                    logging.info(f"User {target_name} not found.")
                    failed_users.append(f"{target_name} ({email_address}): User not found.")

                    logging.info(f"Navigating back to user page for next user processing.")
                    navigate_to_user_page(driver)

            except Exception as e:
                logging.error(f"Error processing user {target_name}: {e}")
                failed_users.append(f"{target_name} ({email_address}): Unexpected error occurred.")

        send_summary_email(successful_users, failed_users)

    except WebDriverException as e:
        logging.info(f"General WebDriver error: {e}")
        send_summary_email([], [f"General WebDriver error: {e}"])
    finally:
        if debugging:
            print(log_stream.getvalue())
        else:
            driver.quit()

if __name__ == "__main__":
    main()
