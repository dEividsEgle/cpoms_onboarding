from idlelib.debugger_r import debugging
import os
import logging
import io
import smtplib
import pyotp
from pathlib import Path
from email.message import EmailMessage

from dotenv import load_dotenv
from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver import ActionChains
from selenium.webdriver.edge.options import Options
from selenium.webdriver.edge.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

debugging = True

log_stream = io.StringIO()
log_format = "%(message)s"

logging.basicConfig(stream=log_stream, level=logging.INFO, format=log_format)

load_dotenv()

LOGIN_PAGE = os.getenv("LOGIN_PAGE")
ACCOUNT_EMAIL = os.getenv("ACCOUNT_EMAIL")
ACCOUNT_PASSWORD = os.getenv("ACCOUNT_PASSWORD")
MFA_SECRET = os.getenv("MFA_SECRET")
USER_PAGE = os.getenv("USER_PAGE")
TARGET_NAMES = os.getenv("TARGET_NAMES").split(",")
EMAIL_ADDRESSES = os.getenv("EMAIL_ADDRESSES").split(",")
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL")

script_directory = Path(__file__).resolve().parent
driver_path = script_directory.joinpath("edgedriver_macarm64", "msedgedriver")

edge_options = Options()
if debugging:
    edge_options.add_experimental_option("detach", True)
else:
    edge_options.add_argument("--headless")

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
            WebDriverWait(driver, 10).until(
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
            return True

    except Exception as e:
        logging.error(f"Error during user creation: {e}")
        return False

def send_message(subject, receiver):
    sender = SENDER_EMAIL

    msg = EmailMessage()
    msg['From'] = sender
    msg['To'] = receiver
    msg['Subject'] = subject
    msg.set_content(log_stream.getvalue())

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(sender, SENDER_PASSWORD)
        smtp.send_message(msg)

    log_stream.truncate(0)
    log_stream.seek(0)

def main():
    service = Service(str(driver_path))
    driver = webdriver.Edge(service=service, options=edge_options)

    try:
        login_to_account(driver)
        navigate_to_user_page(driver)

        user_email_pairs = zip(TARGET_NAMES, EMAIL_ADDRESSES)

        for target_name, email_address in user_email_pairs:
            target_name = target_name.strip()
            email_address = email_address.strip()
            logging.info(f"Processing user {target_name} with email {email_address}...")

            user_found = process_user(driver, target_name)
            if user_found:
                logging.info(f"User {target_name} found, attempting to set email and group.")

                email_and_group_updated = set_email_and_group(driver, email_address)
                if email_and_group_updated:
                    logging.info(f"Email and user group updated successfully for {target_name}.")

                    user_created = create_user(driver)
                    if user_created:
                        logging.info(f"User {target_name} created successfully.")
                        send_message(
                            subject=f"Success: CPOMS User {target_name} Account Has Been Created.",
                            receiver=RECEIVER_EMAIL
                        )
                    else:
                        logging.info(f"Failed to create user {target_name}.")
                        send_message(
                            subject=f"Failure: Unable To Create CPOMS User {target_name}.",
                            receiver=RECEIVER_EMAIL
                        )
                else:
                    logging.info(f"Failed to update email or group for {target_name}.")
                    send_message(
                        subject=f"Failure: Unable To Update Email or Group for CPOMS User {target_name}.",
                        receiver=RECEIVER_EMAIL
                    )
            else:
                logging.info(f"User {target_name} not found.")
                send_message(
                    subject=f"Failure: Unable To Process CPOMS User {target_name}.",
                    receiver=RECEIVER_EMAIL
                )

    except WebDriverException as e:
        logging.info(f"General WebDriver error: {e}")
        send_message(
            subject=f"General Error: Failed To Process CPOMS User.",
            receiver=RECEIVER_EMAIL
        )
    finally:
        if debugging:
            print(log_stream.getvalue())
        else:
            driver.quit()

if __name__ == "__main__":
    main()
