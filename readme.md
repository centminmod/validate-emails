# Email Validation Script

## Overview
The `validate_emails.py` email validation script is a Python-based tool that allows you to validate and classify email addresses using SMTP (Simple Mail Transfer Protocol) checks. It provides a convenient way to verify the existence and deliverability of email addresses, helping you maintain a clean and accurate email list.

## Features
- Validates email addresses using syntax, DNS and SMTP checks
- Validates `-f` from email address's SPF, DKIM, DMARC records and logs them for troubleshooting mail deliverability
- Support local self-hosted email verification + [API support](#api-support) for:
  - [EmailListVerify](https://centminmod.com/emaillistverify) [[example](#emaillistverify-1)] 
  - [MillionVerifier](https://centminmod.com/millionverifier) [[example](#millionverifier)]
  - [MyEmailVerifier](https://centminmod.com/myemailverifier) [[example](#myemailverifier-api)]
  - [CaptainVerify](https://centminmod.com/captainverify) [[example](#captainverify-api)]
  - [Proofy.io](https://centminmod.com/proofy) [[example](#proofy-api)]
- Classifies email addresses into various categories based on the syntax, DNS, and SMTP response
- Supports concurrent processing for faster validation of multiple email addresses
- Provides detailed logging for tracking the validation process
- Allows customization of delay between requests to respect email server limitations
- Supports input of email addresses via command-line arguments or a file
- Identifies disposable email addresses and free domain name provider addresses
- Checks email addresses against custom blacklists and whitelists
- Supports different test modes for syntax, DNS, SMTP, and disposable email checks
- Configurable SMTP port and TLS/SSL support
- Supports SMTP profiles.
- Supports different DNS lookup methods: asyncio, concurrent, and sequential
- Supports different processing modes: thread and asyncio
- Generates SQL queries for updating user status in XenForo forum based email validation results. Allowing you to clean up your Xenforo user database's email addresses.

## Requirements
- Python 3.6 minimum. Script tested on AlmaLinux 8 Python 3.6 and AlmaLinux 9 Python 3.9.

## Usage
1. Open a terminal or command prompt and navigate to the directory where the script is located.

2. Run the script with the desired command-line arguments. 

```
python validate_emails.py 
usage: validate_emails.py [-h] -f FROM_EMAIL [-e EMAILS] [-l LIST_FILE] [-b BATCH_SIZE] [-d] [-v] [-delay DELAY]
                          [--cache-timeout CACHE_TIMEOUT] [-t TIMEOUT] [-r RETRIES] [-tm {syntax,dns,smtp,all,disposable}]
                          [-dns {asyncio,concurrent,sequential}] [-p {thread,asyncio}] [-bl BLACKLIST_FILE] [-wl WHITELIST_FILE]
                          [-smtp {default,ses,generic,rotate}] [-xf] [-xfdb XF_DATABASE] [-xfprefix XF_PREFIX] [-profile]
                          [-wf WORKER_FACTOR] [-api {emaillistverify,millionverifier,captainverify,proofy,myemailverifier}]
                          [-apikey EMAILLISTVERIFY_API_KEY] [-apikey_mv MILLIONVERIFIER_API_KEY] [-apibulk {emaillistverify}]
                          [-apikey_cv CAPTAINVERIFY_API_KEY] [-apikey_pf PROOFY_API_KEY] [-apiuser_pf PROOFY_USER_ID]
                          [-pf_max_connections PROOFY_MAX_CONNECTIONS] [-apikey_mev MYEMAILVERIFIER_API_KEY]
                          [-mev_max_connections MEV_MAX_CONNECTIONS]
validate_emails.py: error: the following arguments are required: -f/--from_email
```

The available arguments are:

  - `-f`, `--from_email` (required):
    - Description: The email address to use in the MAIL FROM command.
  - `-e`, `--emails` (optional):
    - Description: A single email or comma-separated list of emails to check.
  - `-l`, `--list_file` (optional):
    - Description: The path to a file containing emails, one per line.
  - `-b`, `--batch_size` (optional):
    - Description: The number of concurrent processes to use (default is 1).
  - `-d`, `--debug` (optional):
    - Description: Enable debug logging for more verbose output.
  - `-v`, `--verbose` (optional):
    - Description: Enable verbose output.
  - `-delay`, `--delay` (optional):
    - Description: The delay between requests in seconds (default is 1).
  - `--cache-timeout` (optional):
    - Description: Set the caching resolver timeout value (default is 14400).
  - `-t`, `--timeout` (optional):
    - Description: The timeout in seconds for SMTP connection and commands (default is 10).
  - `-r`, `--retries` (optional):
    - Description: The number of retries for temporary failures and timeouts (default is 3).
  - `-tm`, `--test-mode` (optional):
    - Description: The test mode to use for email validation. Available options are:
      - `syntax`: Check email format syntax only.
      - `dns`: Perform DNS validation only (default).
      - `smtp`: Perform SMTP validation only.
      - `all`: Perform all validations.
      - `disposable`: Check if the email is from a disposable domain.
  - `-dns`, `--dns-method` (optional):
    - Description: The DNS lookup method to use. Available options are:
      - `asyncio`: Use asynchronous DNS lookups using the asyncio library (default).
      - `concurrent`: Use concurrent DNS lookups using the concurrent.futures library.
      - `sequential`: Use basic sequential DNS lookups.
  - `-p`, `--process_mode` (optional):
    - Description: The processing mode to use for the `process_emails` function. Available options are:
      - `thread`: Use thread-based processing (default).
      - `asyncio`: Use asyncio-based processing.
  - `-bl`, `--blacklist_file` (optional):
    - Description: The path to a file containing blacklisted domains, one per line.
  - `-wl`, `--whitelist_file` (optional):
    - Description: The path to a file containing whitelisted domains, one per line.
  - `-smtp`, `--smtp_profile` (optional):
    - Description: The SMTP profile to use for email validation. Available options are:
      - `default`: Use the default SMTP settings (default).
      - `ses`: Use Amazon SES SMTP settings via `ses.ini` config file.
      - `generic`: Use generic SMTP settings via `smtp.ini` config file.
      - `rotate`: Use multiple SMTP profile settings via `rotate.ini` config file which you can rotate through.
  - `-xf`, `--xf_sql` (optional):
    - Description: Generate SQL queries for updating `user_state` in XenForo for emails with specific statuses.
  - `-xfdb`, `--xf_database` (optional):
    - Description: The XenForo database name (default is 'DATABNAME').
  - `-xfprefix`, `--xf_prefix` (optional):
    - Description: The XenForo table prefix (default is 'xf_').
  - `-profile`, `--profile` (optional):
    - Description: Enable profiling of the script.
  - `-wf`, `--worker-factor` (optional):
    - Description: The worker factor for calculating the maximum number of worker threads (default is 16).
  - `-api`, `--api` (optional):
    - Description: Specify the API to use for email verification. Available options are:
      - `emaillistverify`: Use the EmailListVerify API.
      - `millionverifier`: Use the MillionVerifier API.
      - `myemailverifier`: Use the MyEmailVerifier API.
      - `captainverify`: Use the CaptainVerify API.
      - `proofy`: Use the Proofy API.
  - `-apibulk`, `--api_bulk` (optional):
    - Description: Use EmailListVerify Bulk file API method.
  - `-apikey`, `--emaillistverify_api_key` (optional):
    - Description: The API key for the EmailListVerify service.
  - `-apikey_mv`, `--millionverifier_api_key` (optional):
    - Description: The API key for the MillionVerifier service.
  - `-apikey_mev`, `--myemailverifier-api-key` (optional):
    - Description: The API key for the MyEmailVerifier service.
  - `-apikey_cv`, `--captainverify_api_key` (optional):
    - Description: The API key for the CaptainVerify service.
  - `-apikey_pf`, `--proofy_api_key` (optional):
    - Description: The API key for the Proofy service.
  - `-apiuser_pf`, `--proofy_user_id` (optional):
    - Description: The Proofy userid.
  - `-pf_max_connections` (optional):
    - Description: Maximum number of concurrent connections for the Proofy.io API (default: 1)
  - `-mev_max_connections` (optional):
    - Description: Maximum number of concurrent connections for the MyEmailVerifier API (default: 1)

Validates `-f` from email address's SPF, DKIM, DMARC records when argument is passed and logs them 

```
python validate_emails.py -f user@domain1.com
```
```
cat email_verification_log_2024-05-05_01-54-51.log

2024-05-05 01:54:51,105 - INFO - SPF record found for user@domain1.com
2024-05-05 01:54:51,105 - INFO - SPF record: "v=spf1 include:_spf.google.com +a +mx ~all"
2024-05-05 01:54:51,142 - ERROR - Error checking DKIM for user@domain1.com with selector default: The DNS response does not contain an answer to the question: default._domainkey.domain1.com. IN TXT
2024-05-05 01:54:51,174 - INFO - DKIM record found for user@domain1.com with selector google
2024-05-05 01:54:51,174 - INFO - DKIM record: "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCMF3nm2Za6EN0udFQLb35Jcy3u63iCzdaojAkVsCISJsHKe2ThgSsriU1MRm32abcd/u2aNEAxJ3jhN7TbkuV8j7xppV5PW+abcd/84lxa2xTlngXOymlJWleoTZUQQPkmkB66IO/XqZVj7RrF/Iru1qpAvJ9aW+6vCZEJFjCZowIDAQAB"
2024-05-05 01:54:51,237 - WARNING - Error checking DMARC for user@domain1.com with record name _dmarc: The DMARC record must be located at _dmarc._dmarc.domain1.com, not _dmarc.domain1.com
2024-05-05 01:54:51,562 - INFO - DMARC record found for user@domain1.com with record name _dmarc.mail
2024-05-05 01:54:51,562 - INFO - DMARC record: v=DMARC1; p=quarantine; sp=none; rua=mailto:re+xxx@inbound.dmarcdigests.com,mailto:re+yyy@dmarc.postmarkapp.com; aspf=r; pct=100
2024-05-05 01:54:51,562 - INFO - DMARC policy check passed for user@domain1.com
```

Example usage for DNS only checks (skipping SMTP checks):
```
python validate_email.py -f sender@example.com -e user1@example.com,user2@example.com -tm dns
```

Example usage for DNS + SMTP checks:
```
python validate_email.py -f sender@example.com -e user1@example.com,user2@example.com -tm all
```

**Notes:**

- If the `-tm` flag is not passed, it defaults to DNS test mode only.
- Tuning `-wf` worker factor value for calculating the maximum number of worker threads can speed up the processing of emails when in `-p thread` process mode or when no `-p` flag is set. Example benchmark of 10,000 email addresses for `-tm dns -p thread` for DNS only tests (using default `-dns asyncio`) using process method = thread took 4mins 40s to complete with work factor `-wf 4`. However, with `-wf 80` time to completion took ~40s on a Intel Core i7 4790K 4C/8T or ~33s on a Intel Xeon E-2276G 6C/12T based dedicated server.

## Output
The script outputs the validation results in JSON format. Each email address is represented by an object with the following fields:

- `email`: The email address.
- `status`: The validation status of the email address. Possible values are:
  - `valid_format`: The email address has a valid format.
  - `invalid_format`: The email address has an invalid format.
  - `valid_dns`: The email address has valid DNS records.
  - `invalid_dns`: The email address has invalid DNS records.
  - `ok`: The email address passed SMTP validation.
  - `unknown_email`: The email address is unknown or doesn't exist.
  - `temporary_failure`: A temporary failure occurred during SMTP validation.
  - `syntax_or_command_error`: An SMTP syntax or command error occurred.
  - `transaction_failed`: The SMTP transaction failed.
  - `timeout`: A timeout occurred during SMTP validation.
  - `skipped_smtp_check`: SMTP validation was skipped based on the test mode.
- `status_code`: SMTP validation check's logged SMTP response code.
- `free_email`: Indicates whether the email address is from a free email provider. Possible values are `yes`, `no`, or `unknown`.
- `disposable_email`: Indicates whether the email address is from a disposable domain. Possible values are `yes`, `no`, or `notchecked`.
- `xf_sql` (optional): The SQL query for updating the user status in XenForo based on the validation result.

## Logging
The script generates a log file named `email_verification_log_<timestamp>.log` in the same directory as the script. The log file contains detailed information about the validation process, including any errors or warnings encountered.

If `-v` verbose mode is used with `-tm all` for SMTP domain MX record checks, an additional debug log file named `email_verification_log_debug_<timestamp>.log` is generated in the same directory as the script. The debug log has extended logging of the SMTP responses.

## Configuration

### -smtp ses

The script supports loading SMTP settings from a configuration file named `ses.ini`. The file should have the following format:

```
[ses]
server = your_ses_smtp_server
port = your_ses_smtp_port
use_tls = True
username = your_ses_username
password = your_ses_password
```

If the `ses` SMTP profile is specified using the `-smtp ses` argument, the script will load the SMTP settings from the `ses.ini` file.

### -smtp rotate

The `rotate.ini` file is used to store multiple SMTP profiles that can be rotated during the email verification process with `-smtp rotate` argument is passed on command line. Each profile represents a different SMTP server configuration.

Here's an example of how the `rotate.ini` file can be populated:

```ini
[profile1]
server = smtp1.example.com
port = 587
use_tls = yes
username = user1@example.com
password = password1

[profile2]
server = smtp2.example.com
port = 465
use_tls = yes
username = user2@example.com
password = password2

[profile3]
server = smtp3.example.com
port = 25
use_tls = no
username = user3@example.com
password = password3
```

In this example, the `rotate.ini` file contains three SMTP profiles: `profile1`, `profile2`, and `profile3`. Each profile is defined as a separate section in the INI file.

The properties for each profile are:
- `server`: The hostname or IP address of the SMTP server.
- `port`: The port number to use for the SMTP connection (e.g., 25, 465, 587).
- `use_tls`: Indicates whether to use TLS encryption for the SMTP connection. Set to `yes` or `no`.
- `username`: The username for SMTP authentication.
- `password`: The password for SMTP authentication.

You can add as many profiles as needed to the `rotate.ini` file, each with its own unique section name and SMTP server settings.

When the `rotate` profile is selected using the `-smtp rotate` option, the script will randomly choose one of the profiles defined in `rotate.ini` for each email verification request. This allows for distributing the email verification load across multiple SMTP servers.

Make sure to populate the `rotate.ini` file with the appropriate SMTP server settings for each profile before using the `rotate` profile option.

### -smtp generic

The `smtp.ini` file is used to store the configuration for a single generic SMTP server that can be used for email verification with `-smtp generic` argument is passed on command line.

Here's an example of how the `smtp.ini` file can be populated:

```ini
[generic]
server = smtp.example.com
port = 587
use_tls = yes
username = user@example.com
password = password
```

In this example, the `smtp.ini` file contains a single section named `[generic]`, which represents the generic SMTP profile.

The properties for the generic profile are:
- `server`: The hostname or IP address of the SMTP server.
- `port`: The port number to use for the SMTP connection (e.g., 25, 465, 587).
- `use_tls`: Indicates whether to use TLS encryption for the SMTP connection. Set to `yes` or `no`.
- `username`: The username for SMTP authentication.
- `password`: The password for SMTP authentication.

When the `generic` profile is selected using the `-smtp generic` option, the script will use the SMTP server settings defined in the `smtp.ini` file for all email verification requests.

Make sure to populate the `smtp.ini` file with the appropriate SMTP server settings before using the `generic` profile option.

## Customization
You can customize the behavior of the script by modifying the following variables in the code:

- `DEFAULT_DELAY`: The default delay between requests in seconds (default is 1).
- `LARGE_PROVIDER_DELAY`: The delay for large email providers in seconds (default is 2).
- `LARGE_PROVIDERS`: A list of large email providers that require a longer delay between requests.

## Troubleshooting
If you encounter any issues or errors while running the script, consider the following:

- Ensure that you have installed all the required Python packages.
- Check the log file for detailed error messages and traceback information.
- Verify that the email addresses provided are valid and properly formatted.
- Make sure you have a stable internet connection for accurate DNS and SMTP validations.
- If you are using custom blacklist or whitelist files, ensure that they exist and contain valid domain entries.

## `domain_responses` function

1. The `smtp_check` function now accepts a `domain_responses` parameter, which is a dictionary to store the SMTP responses for each domain. It records the SMTP response code and message for each domain.

2. The `process_emails` function creates a `domain_responses` dictionary to store the SMTP responses per domain. It passes this dictionary to the `validate_and_classify` function.

3. After processing the emails, the `process_emails` function analyzes the SMTP responses for each domain. It calculates the failure rate based on the SMTP response codes. If the failure rate exceeds a predefined threshold (e.g., 5% in this example), it logs a warning message indicating that the verification strategy needs to be adjusted for that domain.

4. The `validate_and_classify` function now accepts the `domain_responses` parameter and passes it to the `smtp_check` function.

With these changes, the script will proactively monitor SMTP responses and adjust the verification strategy based on the feedback from the servers.

Example in log

```
grep failure email_verification_log_2024-05-03_08-45-05.log

2024-05-03 08:45:07,910 - INFO - Acceptable failure rate (0.00%) for domain gmail.com.
```

# Example Usage 

AWS SES SMTP support and Xenforo support to display MySQL query for bad emails only to set their status to `email_bounce` passing flags `-xf` and `-xfdb xenforo` and `-xfprefix xf_`

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -smtp ses -xf -xfdb xenforo -xfprefix xf_
```

`ses.ini`

```
[ses]
server = email-smtp.us-west-2.amazonaws.com
port = 587
use_tls = true
username = YOUR_AWS_SES_SMTP_USERNAME
password = YOUR_AWS_SES_SMTP_PASSWORD
```

### Xenforo

Xenforo support to display MySQL query for bad emails only to set their status to `email_bounce` passing flags `-xf` and `-xfdb xenforo` and `-xfprefix xf_` with `disposable_email` status field

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -xf -xfdb xenforo -xfprefix xf_
[
    {
        "email": "user@mailsac.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "yes"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid_format",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "no"
    },
    {
        "email": "user+to@domain1.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com'; xenforo\""
    },
    {
        "email": "abc@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com'; xenforo\""
    },
    {
        "email": "123@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com'; xenforo\""
    },
    {
        "email": "pop@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com'; xenforo\""
    },
    {
        "email": "pip@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com'; xenforo\""
    },
    {
        "email": "user@tempr.email",
        "status": "ok",
        "status_code": 250,
        "free_email": "no",
        "disposable_email": "yes"
    },
    {
        "email": "info@domain2.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "yes",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com'; xenforo\""
    },
    {
        "email": "user@yahoo.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "no"
    }
]
```

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -xf -xfdb xenforo -xfprefix xf_ | jq 'map({ status: .status }) | group_by(.status) | map({ status: .[0].status, count: length })'

[
  {
    "status": "invalid_format",
    "count": 1
  },
  {
    "status": "ok",
    "count": 8
  },
  {
    "status": "unknown_email",
    "count": 6
  }
]
```

## EmailListVerify

Here's a comparison using a commercial paid service [EmailListVerify](https://centminmod.com/emaillistverify) for the same `emaillist.txt` tested above. You can sign up using my affiliate link for [EmailListVerify](https://centminmod.com/emaillistverify) and free accounts get 100 free email verifications for starters.

```csv
disposable,"user@mailsac.com"
dead_server,"xyz@centmil1.com"
ok,"user+to@domain1.com"
disposable,"user@tempr.email"
ok,"info@domain2.com"
email_disabled,"xyz@domain1.com"
email_disabled,"abc@domain1.com"
email_disabled,"123@domain1.com"
email_disabled,"pop@domain1.com"
email_disabled,"pip@domain1.com"
ok,"user@gmail.com"
email_disabled,"op999@gmail.com"
ok,"user@yahoo.com"
ok,"user1@outlook.com"
ok,"user2@hotmail.com"
```

Where [EmailListVerify](https://centminmod.com/emaillistverify) status codes are as follows:

- `ok`  All is OK. The server is saying that it is ready to receive a letter to,this address, and no tricks have been detected
- `error` The server is saying that delivery failed, but no information about,the email exists
- `smtp_error`  The SMTP answer from the server is invalid or the destination server,reported an internal error to us
- `smtp_protocol` The destination server allowed us to connect but the SMTP,session was closed before the email was verified
- `unknown_email` The server said that the delivery failed and that the email address does,not exist
- `attempt_rejected`  The delivery failed; the reason is similar to “rejected”
- `relay_error` The delivery failed because a relaying problem took place
- `antispam_system` Some anti-spam technology is blocking the,verification progress
- `email_disabled`  The email account is suspended, disabled, or limited and can not,receive emails
- `domain_error`  The email server for the whole domain is not installed or is,incorrect, so no emails are deliverable
- `ok_for_all`  The email server is saying that it is ready to accept letters,to any email address
- `dead_server` The email server is dead, and no connection to it could be established
- `syntax_error`  There is a syntax error in the email address
- `unknown` The email delivery failed, but no reason was given
- `accept_all`  The server is set to accept all emails at a specific domain.,These domains accept any email you send to them
- `disposable`  The email is a temporary address to receive letters and expires,after certain time period
- `spam_traps`  The email address is maintained by an ISP or a third party,which neither clicks nor opens emails

Filter for disposable_email = yes

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -xf -xfdb xenforo -xfprefix xf_ -tm all | jq '.[] | select(.disposable_email == "yes")'
{
  "email": "user@mailsac.com",
  "status": "ok",
  "status_code": 250,
  "free_email": "yes",
  "disposable_email": "yes"
}
{
  "email": "user@tempr.email",
  "status": "ok",
  "status_code": 250,
  "free_email": "no",
  "disposable_email": "yes"
}
```

Using `jq` tool to only list MySQL queries for bad emails only

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -xf -xfdb xenforo -xfprefix xf_ | jq -r '.[] | select(.xf_sql) | .xf_sql'

mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com'; xenforo"
```

Filter using `jq` tool for `free_email = yes` emails only

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all | jq '.[] | select(.free_email == "yes")'
{
  "email": "user@mailsac.com",
  "status": "ok",
  "status_code": 250,
  "free_email": "yes",
  "disposable_email": "yes"
}
{
  "email": "user@gmail.com",
  "status": "ok",
  "status_code": 250,
  "free_email": "yes",
  "disposable_email": "no"
}
{
  "email": "op999@gmail.com",
  "status": "unknown_email",
  "status_code": 550,
  "free_email": "yes",
  "disposable_email": "no"
}
{
  "email": "user@yahoo.com",
  "status": "ok",
  "status_code": 250,
  "free_email": "yes",
  "disposable_email": "no"
}
{
  "email": "user1@outlook.com",
  "status": "ok",
  "status_code": 250,
  "free_email": "yes",
  "disposable_email": "no"
}
{
  "email": "user2@hotmail.com",
  "status": "ok",
  "status_code": 250,
  "free_email": "yes",
  "disposable_email": "no"
}
```

`-tm disposable` mode only skipping SMTP server checks with email addresses in file `emaillist.txt`

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm disposable -v

[
    {
        "email": "user@mailsac.com",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "yes"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user+to@domain1.com",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "abc@domain1.com",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "123@domain1.com",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "pop@domain1.com",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "pip@domain1.com",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@tempr.email",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes"
    },
    {
        "email": "info@domain2.com",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user@yahoo.com",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "not_disposable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    }
]
```

`-tm dns` mode only skipping SMTP server checks with email addresses in file `emaillist.txt`

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm dns -v
[
    {
        "email": "user@mailsac.com",
        "status": "valid_dns",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "notchecked"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid_format",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "notchecked"
    },
    {
        "email": "user+to@domain1.com",
        "status": "valid_dns",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "xyz@domain1.com",
        "status": "valid_dns",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "abc@domain1.com",
        "status": "valid_dns",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "123@domain1.com",
        "status": "valid_dns",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "pop@domain1.com",
        "status": "valid_dns",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "pip@domain1.com",
        "status": "valid_dns",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "user@tempr.email",
        "status": "valid_dns",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "info@domain2.com",
        "status": "valid_dns",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "user@gmail.com",
        "status": "valid_dns",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "notchecked"
    },
    {
        "email": "op999@gmail.com",
        "status": "valid_dns",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "notchecked"
    },
    {
        "email": "user@yahoo.com",
        "status": "valid_dns",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "notchecked"
    },
    {
        "email": "user1@outlook.com",
        "status": "valid_dns",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "notchecked"
    },
    {
        "email": "user2@hotmail.com",
        "status": "valid_dns",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "notchecked"
    }
]
```

Logging SMTP server response displayed in `-v` verbose mode with email addresses in file `emaillist.txt` will create a 2nd debug log `email_verification_log_debug_*.log` with entries.

```
ls -lhArt | tail -2
-rw-r--r-- 1 root      root      9.8K May  4 23:35 email_verification_log_debug_2024-05-04_23-35-47.log
-rw-r--r-- 1 root      root      6.0K May  4 23:35 email_verification_log_2024-05-04_23-35-47.log
```

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -v
[
    {
        "email": "user@mailsac.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "yes"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid_format",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "no"
    },
    {
        "email": "user+to@domain1.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "abc@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "123@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "pop@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "pip@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@tempr.email",
        "status": "ok",
        "status_code": 250,
        "free_email": "no",
        "disposable_email": "yes"
    },
    {
        "email": "info@domain2.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user@yahoo.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "no"
    }
]
```

Regular non-verbose log `email_verification_log_2024-05-04_23-35-47.log` will also show the `smtp` profile used to do the SMTP check testing as well as `Acceptable failure rate` metrics per domain.

```
cat email_verification_log_2024-05-04_23-35-47.log
2024-05-04 23:35:48,080 - INFO - Disposable email address: user@mailsac.com
2024-05-04 23:35:48,082 - INFO - Disposable email address: user@tempr.email
2024-05-04 23:35:48,626 - INFO - SMTP response for user@mailsac.com using profile [default]: 250, b'Accepted'
2024-05-04 23:35:49,022 - INFO - SMTP response for user@tempr.email using profile [default]: 250, b'2.1.5 Ok'
2024-05-04 23:35:49,082 - INFO - Validating user+to@domain1.com
2024-05-04 23:35:49,082 - INFO - Email DNS is valid: user+to@domain1.com
2024-05-04 23:35:49,082 - INFO - Validating 123@domain1.com
2024-05-04 23:35:49,082 - INFO - Validating abc@domain1.com
2024-05-04 23:35:49,082 - INFO - Validating xyz@domain1.com
2024-05-04 23:35:49,082 - INFO - Validating pop@domain1.com
2024-05-04 23:35:49,082 - INFO - Email DNS is valid: pop@domain1.com
2024-05-04 23:35:49,082 - INFO - Email DNS is valid: 123@domain1.com
2024-05-04 23:35:49,082 - INFO - Email DNS is valid: abc@domain1.com
2024-05-04 23:35:49,082 - INFO - Email DNS is valid: xyz@domain1.com
2024-05-04 23:35:49,082 - INFO - Validating pip@domain1.com
2024-05-04 23:35:49,083 - INFO - Validating info@domain2.com
2024-05-04 23:35:49,083 - INFO - Email DNS is valid: pip@domain1.com
2024-05-04 23:35:49,083 - INFO - Email DNS is valid: info@domain2.com
2024-05-04 23:35:49,084 - INFO - Validating user2@hotmail.com
2024-05-04 23:35:49,084 - INFO - Email DNS is valid: user2@hotmail.com
2024-05-04 23:35:49,646 - INFO - SMTP response for pop@domain1.com using profile [default]: 550, b"5.1.1 The email account that you tried to reach does not exist. Please try\n5.1.1 double-checking the recipient's email address for typos or\n5.1.1 unnecessary spaces. For more information, go to\n5.1.1  https://support.google.com/mail/?p=NoSuchUser h14-20020a05640250ce00b00572b21fb7d5si3202708edb.683 - gsmtp"
2024-05-04 23:35:49,666 - INFO - SMTP response for 123@domain1.com using profile [default]: 550, b"5.1.1 The email account that you tried to reach does not exist. Please try\n5.1.1 double-checking the recipient's email address for typos or\n5.1.1 unnecessary spaces. For more information, go to\n5.1.1  https://support.google.com/mail/?p=NoSuchUser sh43-20020a1709076eab00b00a597a01b74csi2965444ejc.273 - gsmtp"
2024-05-04 23:35:49,672 - INFO - SMTP response for abc@domain1.com using profile [default]: 550, b"5.1.1 The email account that you tried to reach does not exist. Please try\n5.1.1 double-checking the recipient's email address for typos or\n5.1.1 unnecessary spaces. For more information, go to\n5.1.1  https://support.google.com/mail/?p=NoSuchUser gt34-20020a1709072da200b00a597ff2fc04si2617860ejc.981 - gsmtp"
2024-05-04 23:35:49,675 - INFO - SMTP response for pip@domain1.com using profile [default]: 550, b"5.1.1 The email account that you tried to reach does not exist. Please try\n5.1.1 double-checking the recipient's email address for typos or\n5.1.1 unnecessary spaces. For more information, go to\n5.1.1  https://support.google.com/mail/?p=NoSuchUser p14-20020aa7d30e000000b00572d0cb1e66si1718373edq.661 - gsmtp"
2024-05-04 23:35:49,694 - INFO - SMTP response for xyz@domain1.com using profile [default]: 550, b"5.1.1 The email account that you tried to reach does not exist. Please try\n5.1.1 double-checking the recipient's email address for typos or\n5.1.1 unnecessary spaces. For more information, go to\n5.1.1  https://support.google.com/mail/?p=NoSuchUser wg10-20020a17090705ca00b00a5999e2028dsi2138359ejb.514 - gsmtp"
2024-05-04 23:35:49,752 - INFO - SMTP response for info@domain2.com using profile [default]: 250, b'2.1.5 OK j7-20020a5d5647000000b0034cfd826251si3647095wrw.519 - gsmtp'
2024-05-04 23:35:49,753 - INFO - SMTP response for user+to@domain1.com using profile [default]: 250, b'2.1.5 OK m8-20020a056402430800b005721e7edb0fsi3177955edc.665 - gsmtp'
2024-05-04 23:35:49,761 - INFO - SMTP response for user2@hotmail.com using profile [default]: 250, b'2.1.5 Recipient OK'
2024-05-04 23:35:50,085 - INFO - Validating user@gmail.com
2024-05-04 23:35:50,085 - INFO - Email DNS is valid: user@gmail.com
2024-05-04 23:35:50,085 - INFO - Validating op999@gmail.com
2024-05-04 23:35:50,085 - INFO - Validating user@yahoo.com
2024-05-04 23:35:50,086 - INFO - Email DNS is valid: op999@gmail.com
2024-05-04 23:35:50,086 - INFO - Email DNS is valid: user@yahoo.com
2024-05-04 23:35:50,086 - INFO - Validating user1@outlook.com
2024-05-04 23:35:50,086 - INFO - Email DNS is valid: user1@outlook.com
2024-05-04 23:35:50,545 - INFO - SMTP response for user1@outlook.com using profile [default]: 250, b'2.1.5 Recipient OK'
2024-05-04 23:35:50,659 - INFO - SMTP response for op999@gmail.com using profile [default]: 550, b"5.1.1 The email account that you tried to reach does not exist. Please try\n5.1.1 double-checking the recipient's email address for typos or\n5.1.1 unnecessary spaces. For more information, go to\n5.1.1  https://support.google.com/mail/?p=NoSuchUser w9-20020a5d4049000000b0034ddab36ff8si3678827wrp.499 - gsmtp"
2024-05-04 23:35:50,801 - INFO - SMTP response for user@gmail.com using profile [default]: 250, b'2.1.5 OK d7-20020a05600c34c700b0041d7d5787bfsi3791910wmq.193 - gsmtp'
2024-05-04 23:35:50,802 - INFO - SMTP response for user@yahoo.com using profile [default]: 250, b'recipient <user@yahoo.com> ok'
2024-05-04 23:35:50,802 - INFO - Acceptable failure rate (0.00%) for domain mailsac.com.
2024-05-04 23:35:50,802 - INFO - Acceptable failure rate (0.00%) for domain tempr.email.
2024-05-04 23:35:50,802 - INFO - Acceptable failure rate (0.00%) for domain domain1.com.
2024-05-04 23:35:50,802 - INFO - Acceptable failure rate (0.00%) for domain domain2.com.
2024-05-04 23:35:50,802 - INFO - Acceptable failure rate (0.00%) for domain hotmail.com.
2024-05-04 23:35:50,803 - INFO - Acceptable failure rate (0.00%) for domain outlook.com.
2024-05-04 23:35:50,803 - INFO - Acceptable failure rate (0.00%) for domain gmail.com.
2024-05-04 23:35:50,803 - INFO - Acceptable failure rate (0.00%) for domain yahoo.com.
```

Verbose debug log `email_verification_log_debug_2024-05-04_23-35-47.log`

```
cat email_verification_log_debug_2024-05-04_23-35-47.log
2024-05-04 23:35:48,080 - DEBUG - Connecting to SMTP server alt.mailsac.com. on port 25
2024-05-04 23:35:48,083 - DEBUG - Connecting to SMTP server mx.discard.email. on port 25
2024-05-04 23:35:48,328 - DEBUG - SMTP connection established
2024-05-04 23:35:48,403 - DEBUG - EHLO command sent
2024-05-04 23:35:48,403 - DEBUG - Sending MAIL FROM command: user@domain1.com
2024-05-04 23:35:48,477 - DEBUG - MAIL FROM command sent successfully
2024-05-04 23:35:48,477 - DEBUG - Sending RCPT TO command for: user@mailsac.com
2024-05-04 23:35:48,552 - DEBUG - RCPT TO response: 250, b'Accepted'
2024-05-04 23:35:48,626 - DEBUG - SMTP session closed
2024-05-04 23:35:48,642 - DEBUG - SMTP connection established
2024-05-04 23:35:48,737 - DEBUG - EHLO command sent
2024-05-04 23:35:48,737 - DEBUG - Sending MAIL FROM command: user@domain1.com
2024-05-04 23:35:48,832 - DEBUG - MAIL FROM command sent successfully
2024-05-04 23:35:48,832 - DEBUG - Sending RCPT TO command for: user@tempr.email
2024-05-04 23:35:48,927 - DEBUG - RCPT TO response: 250, b'2.1.5 Ok'
2024-05-04 23:35:49,022 - DEBUG - SMTP session closed
2024-05-04 23:35:49,082 - DEBUG - Connecting to SMTP server aspmx5.googlemail.com. on port 25
2024-05-04 23:35:49,083 - DEBUG - Connecting to SMTP server aspmx5.googlemail.com. on port 25
2024-05-04 23:35:49,083 - DEBUG - Connecting to SMTP server aspmx5.googlemail.com. on port 25
2024-05-04 23:35:49,083 - DEBUG - Connecting to SMTP server aspmx5.googlemail.com. on port 25
2024-05-04 23:35:49,083 - DEBUG - Connecting to SMTP server aspmx5.googlemail.com. on port 25
2024-05-04 23:35:49,084 - DEBUG - Connecting to SMTP server aspmx5.googlemail.com. on port 25
2024-05-04 23:35:49,084 - DEBUG - Connecting to SMTP server aspmx2.googlemail.com. on port 25
2024-05-04 23:35:49,084 - DEBUG - Connecting to SMTP server hotmail-com.olc.protection.outlook.com. on port 25
2024-05-04 23:35:49,277 - DEBUG - SMTP connection established
2024-05-04 23:35:49,277 - DEBUG - SMTP connection established
2024-05-04 23:35:49,285 - DEBUG - SMTP connection established
2024-05-04 23:35:49,291 - DEBUG - SMTP connection established
2024-05-04 23:35:49,294 - DEBUG - SMTP connection established
2024-05-04 23:35:49,305 - DEBUG - SMTP connection established
2024-05-04 23:35:49,307 - DEBUG - SMTP connection established
2024-05-04 23:35:49,367 - DEBUG - EHLO command sent
2024-05-04 23:35:49,367 - DEBUG - Sending MAIL FROM command: user@domain1.com
2024-05-04 23:35:49,367 - DEBUG - EHLO command sent
2024-05-04 23:35:49,367 - DEBUG - Sending MAIL FROM command: user@domain1.com
2024-05-04 23:35:49,382 - DEBUG - EHLO command sent
2024-05-04 23:35:49,382 - DEBUG - Sending MAIL FROM command: user@domain1.com
2024-05-04 23:35:49,383 - DEBUG - EHLO command sent
2024-05-04 23:35:49,384 - DEBUG - Sending MAIL FROM command: user@domain1.com
2024-05-04 23:35:49,397 - DEBUG - EHLO command sent
2024-05-04 23:35:49,397 - DEBUG - Sending MAIL FROM command: user@domain1.com
2024-05-04 23:35:49,399 - DEBUG - EHLO command sent
2024-05-04 23:35:49,399 - DEBUG - Sending MAIL FROM command: user@domain1.com
2024-05-04 23:35:49,401 - DEBUG - EHLO command sent
2024-05-04 23:35:49,401 - DEBUG - Sending MAIL FROM command: user@domain1.com
2024-05-04 23:35:49,455 - DEBUG - MAIL FROM command sent successfully
2024-05-04 23:35:49,455 - DEBUG - Sending RCPT TO command for: user+to@domain1.com
2024-05-04 23:35:49,455 - DEBUG - MAIL FROM command sent successfully
2024-05-04 23:35:49,455 - DEBUG - Sending RCPT TO command for: pop@domain1.com
2024-05-04 23:35:49,473 - DEBUG - MAIL FROM command sent successfully
2024-05-04 23:35:49,473 - DEBUG - Sending RCPT TO command for: 123@domain1.com
2024-05-04 23:35:49,474 - DEBUG - MAIL FROM command sent successfully
2024-05-04 23:35:49,474 - DEBUG - Sending RCPT TO command for: abc@domain1.com
2024-05-04 23:35:49,485 - DEBUG - MAIL FROM command sent successfully
2024-05-04 23:35:49,485 - DEBUG - Sending RCPT TO command for: pip@domain1.com
2024-05-04 23:35:49,494 - DEBUG - MAIL FROM command sent successfully
2024-05-04 23:35:49,494 - DEBUG - Sending RCPT TO command for: xyz@domain1.com
2024-05-04 23:35:49,500 - DEBUG - MAIL FROM command sent successfully
2024-05-04 23:35:49,500 - DEBUG - Sending RCPT TO command for: info@domain2.com
2024-05-04 23:35:49,530 - DEBUG - SMTP connection established
2024-05-04 23:35:49,558 - DEBUG - RCPT TO response: 550, b"5.1.1 The email account that you tried to reach does not exist. Please try\n5.1.1 double-checking the recipient's email address for typos or\n5.1.1 unnecessary spaces. For more information, go to\n5.1.1  https://support.google.com/mail/?p=NoSuchUser h14-20020a05640250ce00b00572b21fb7d5si3202708edb.683 - gsmtp"
2024-05-04 23:35:49,576 - DEBUG - RCPT TO response: 550, b"5.1.1 The email account that you tried to reach does not exist. Please try\n5.1.1 double-checking the recipient's email address for typos or\n5.1.1 unnecessary spaces. For more information, go to\n5.1.1  https://support.google.com/mail/?p=NoSuchUser sh43-20020a1709076eab00b00a597a01b74csi2965444ejc.273 - gsmtp"
2024-05-04 23:35:49,580 - DEBUG - RCPT TO response: 550, b"5.1.1 The email account that you tried to reach does not exist. Please try\n5.1.1 double-checking the recipient's email address for typos or\n5.1.1 unnecessary spaces. For more information, go to\n5.1.1  https://support.google.com/mail/?p=NoSuchUser gt34-20020a1709072da200b00a597ff2fc04si2617860ejc.981 - gsmtp"
2024-05-04 23:35:49,586 - DEBUG - EHLO command sent
2024-05-04 23:35:49,586 - DEBUG - Sending MAIL FROM command: user@domain1.com
2024-05-04 23:35:49,587 - DEBUG - RCPT TO response: 550, b"5.1.1 The email account that you tried to reach does not exist. Please try\n5.1.1 double-checking the recipient's email address for typos or\n5.1.1 unnecessary spaces. For more information, go to\n5.1.1  https://support.google.com/mail/?p=NoSuchUser p14-20020aa7d30e000000b00572d0cb1e66si1718373edq.661 - gsmtp"
2024-05-04 23:35:49,600 - DEBUG - RCPT TO response: 550, b"5.1.1 The email account that you tried to reach does not exist. Please try\n5.1.1 double-checking the recipient's email address for typos or\n5.1.1 unnecessary spaces. For more information, go to\n5.1.1  https://support.google.com/mail/?p=NoSuchUser wg10-20020a17090705ca00b00a5999e2028dsi2138359ejb.514 - gsmtp"
2024-05-04 23:35:49,639 - DEBUG - MAIL FROM command sent successfully
2024-05-04 23:35:49,639 - DEBUG - Sending RCPT TO command for: user2@hotmail.com
2024-05-04 23:35:49,646 - DEBUG - SMTP session closed
2024-05-04 23:35:49,651 - DEBUG - RCPT TO response: 250, b'2.1.5 OK j7-20020a5d5647000000b0034cfd826251si3647095wrw.519 - gsmtp'
2024-05-04 23:35:49,665 - DEBUG - RCPT TO response: 250, b'2.1.5 OK m8-20020a056402430800b005721e7edb0fsi3177955edc.665 - gsmtp'
2024-05-04 23:35:49,666 - DEBUG - SMTP session closed
2024-05-04 23:35:49,672 - DEBUG - SMTP session closed
2024-05-04 23:35:49,675 - DEBUG - SMTP session closed
2024-05-04 23:35:49,694 - DEBUG - SMTP session closed
2024-05-04 23:35:49,709 - DEBUG - RCPT TO response: 250, b'2.1.5 Recipient OK'
2024-05-04 23:35:49,752 - DEBUG - SMTP session closed
2024-05-04 23:35:49,753 - DEBUG - SMTP session closed
2024-05-04 23:35:49,761 - DEBUG - SMTP session closed
2024-05-04 23:35:50,085 - DEBUG - Connecting to SMTP server alt2.gmail-smtp-in.l.google.com. on port 25
2024-05-04 23:35:50,086 - DEBUG - Connecting to SMTP server alt2.gmail-smtp-in.l.google.com. on port 25
2024-05-04 23:35:50,086 - DEBUG - Connecting to SMTP server mta6.am0.yahoodns.net. on port 25
2024-05-04 23:35:50,086 - DEBUG - Connecting to SMTP server outlook-com.olc.protection.outlook.com. on port 25
2024-05-04 23:35:50,314 - DEBUG - SMTP connection established
2024-05-04 23:35:50,314 - DEBUG - SMTP connection established
2024-05-04 23:35:50,402 - DEBUG - EHLO command sent
2024-05-04 23:35:50,402 - DEBUG - Sending MAIL FROM command: user@domain1.com
2024-05-04 23:35:50,407 - DEBUG - EHLO command sent
2024-05-04 23:35:50,407 - DEBUG - Sending MAIL FROM command: user@domain1.com
2024-05-04 23:35:50,451 - DEBUG - SMTP connection established
2024-05-04 23:35:50,472 - DEBUG - EHLO command sent
2024-05-04 23:35:50,472 - DEBUG - Sending MAIL FROM command: user@domain1.com
2024-05-04 23:35:50,484 - DEBUG - SMTP connection established
2024-05-04 23:35:50,486 - DEBUG - MAIL FROM command sent successfully
2024-05-04 23:35:50,486 - DEBUG - Sending RCPT TO command for: op999@gmail.com
2024-05-04 23:35:50,492 - DEBUG - MAIL FROM command sent successfully
2024-05-04 23:35:50,493 - DEBUG - Sending RCPT TO command for: user1@outlook.com
2024-05-04 23:35:50,497 - DEBUG - MAIL FROM command sent successfully
2024-05-04 23:35:50,498 - DEBUG - Sending RCPT TO command for: user@gmail.com
2024-05-04 23:35:50,525 - DEBUG - RCPT TO response: 250, b'2.1.5 Recipient OK'
2024-05-04 23:35:50,545 - DEBUG - SMTP session closed
2024-05-04 23:35:50,561 - DEBUG - EHLO command sent
2024-05-04 23:35:50,561 - DEBUG - Sending MAIL FROM command: user@domain1.com
2024-05-04 23:35:50,575 - DEBUG - RCPT TO response: 550, b"5.1.1 The email account that you tried to reach does not exist. Please try\n5.1.1 double-checking the recipient's email address for typos or\n5.1.1 unnecessary spaces. For more information, go to\n5.1.1  https://support.google.com/mail/?p=NoSuchUser w9-20020a5d4049000000b0034ddab36ff8si3678827wrp.499 - gsmtp"
2024-05-04 23:35:50,641 - DEBUG - MAIL FROM command sent successfully
2024-05-04 23:35:50,641 - DEBUG - Sending RCPT TO command for: user@yahoo.com
2024-05-04 23:35:50,659 - DEBUG - SMTP session closed
2024-05-04 23:35:50,710 - DEBUG - RCPT TO response: 250, b'2.1.5 OK d7-20020a05600c34c700b0041d7d5787bfsi3791910wmq.193 - gsmtp'
2024-05-04 23:35:50,720 - DEBUG - RCPT TO response: 250, b'recipient <user@yahoo.com> ok'
2024-05-04 23:35:50,801 - DEBUG - SMTP session closed
2024-05-04 23:35:50,802 - DEBUG - SMTP session closed
```

syntax only test without smtp and dns test

```
python validate_emails.py -f user@domain.com -e user+to@domain.com -tm syntax
[
    {
        "email": "user@mailsac.com",
        "status": "valid_format",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "notchecked"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "valid_format",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "user+to@domain1.com",
        "status": "valid_format",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "xyz@domain1.com",
        "status": "valid_format",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "abc@domain1.com",
        "status": "valid_format",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "123@domain1.com",
        "status": "valid_format",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "pop@domain1.com",
        "status": "valid_format",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "pip@domain1.com",
        "status": "valid_format",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "user@tempr.email",
        "status": "valid_format",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "info@domain2.com",
        "status": "valid_format",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "notchecked"
    },
    {
        "email": "user@gmail.com",
        "status": "valid_format",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "notchecked"
    },
    {
        "email": "op999@gmail.com",
        "status": "valid_format",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "notchecked"
    },
    {
        "email": "user@yahoo.com",
        "status": "valid_format",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "notchecked"
    },
    {
        "email": "user1@outlook.com",
        "status": "valid_format",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "notchecked"
    },
    {
        "email": "user2@hotmail.com",
        "status": "valid_format",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "notchecked"
    }
]
```

# API Support

Script now has added external Email cleaning service API support. 

## EmailListVerify

First one is [EmailListVerify](https://centminmod.com/emaillistverify) where you set `-api emaillistverify -apikey $elvkey` where `$elvkey` is generated API key. 

The `status` field value comes from EmailListVerify API check while `free_email` and `disposable_email` field values from from script's own database check. The `status_code` is `null` as it's not applicable in `-api` mode.

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api emaillistverify -apikey $elvkey -v
[
    {
        "email": "user@mailsac.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "yes"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user+to@domain1.com",
        "status": "valid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "abc@domain1.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "123@domain1.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "pop@domain1.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "pip@domain1.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@tempr.email",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes"
    },
    {
        "email": "info@domain2.com",
        "status": "valid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user@yahoo.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    }
]
```

Where [EmailListVerify](https://centminmod.com/emaillistverify) status codes are as follows:

- `ok`  All is OK. The server is saying that it is ready to receive a letter to,this address, and no tricks have been detected
- `error` The server is saying that delivery failed, but no information about,the email exists
- `smtp_error`  The SMTP answer from the server is invalid or the destination server,reported an internal error to us
- `smtp_protocol` The destination server allowed us to connect but the SMTP,session was closed before the email was verified
- `unknown_email` The server said that the delivery failed and that the email address does,not exist
- `attempt_rejected`  The delivery failed; the reason is similar to “rejected”
- `relay_error` The delivery failed because a relaying problem took place
- `antispam_system` Some anti-spam technology is blocking the,verification progress
- `email_disabled`  The email account is suspended, disabled, or limited and can not,receive emails
- `domain_error`  The email server for the whole domain is not installed or is,incorrect, so no emails are deliverable
- `ok_for_all`  The email server is saying that it is ready to accept letters,to any email address
- `dead_server` The email server is dead, and no connection to it could be established
- `syntax_error`  There is a syntax error in the email address
- `unknown` The email delivery failed, but no reason was given
- `accept_all`  The server is set to accept all emails at a specific domain.,These domains accept any email you send to them
- `disposable`  The email is a temporary address to receive letters and expires,after certain time period
- `spam_traps`  The email address is maintained by an ISP or a third party,which neither clicks nor opens emails

[EmailListVerify](https://centminmod.com/emaillistverify) API integration via `-api` and `apikey` arguments combined with Xenforo flags to display the MySQL query to update invalid user's email addresses to `email_bounce` status in Xenforo database.

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api emaillistverify -apikey $elvkey -xf -xfdb xenforo -xfprefix xf_
[
    {
        "email": "user@mailsac.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com'; xenforo\""
    },
    {
        "email": "xyz@centmil1.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com'; xenforo\""
    },
    {
        "email": "user+to@domain1.com",
        "status": "valid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com'; xenforo\""
    },
    {
        "email": "abc@domain1.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com'; xenforo\""
    },
    {
        "email": "123@domain1.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com'; xenforo\""
    },
    {
        "email": "pop@domain1.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com'; xenforo\""
    },
    {
        "email": "pip@domain1.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com'; xenforo\""
    },
    {
        "email": "user@tempr.email",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email'; xenforo\""
    },
    {
        "email": "info@domain2.com",
        "status": "valid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com'; xenforo\""
    },
    {
        "email": "user@yahoo.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    }
]
```

Using `jq` tool to just filter for MySQL queries.

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api emaillistverify -apikey $elvkey -xf -xfdb xenforo -xfprefix xf_ | jq -r '.[] | select(.xf_sql) | .xf_sql'
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com'; xenforo"
```

Looks like Emaillistverify might be correct = `unknown` for status value. So they differentiate disposable emails = `unknown` I think regardless of whether the email passes SMTP check. Guess that makes sense, so I should also mark disposable emails so they show `xf_sql` query

Updated local test code as such to mark `disposable_email = yes` and display `xf_sql` query.

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -xf -xfdb xenforo -xfprefix xf_
[
    {
        "email": "user@mailsac.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com'; xenforo\""
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid_format",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "no"
    },
    {
        "email": "user+to@domain1.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com'; xenforo\""
    },
    {
        "email": "abc@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com'; xenforo\""
    },
    {
        "email": "123@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com'; xenforo\""
    },
    {
        "email": "pop@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com'; xenforo\""
    },
    {
        "email": "pip@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com'; xenforo\""
    },
    {
        "email": "user@tempr.email",
        "status": "ok",
        "status_code": 250,
        "free_email": "no",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email'; xenforo\""
    },
    {
        "email": "info@domain2.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "yes",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com'; xenforo\""
    },
    {
        "email": "user@yahoo.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "no"
    }
]
```

### EmailListVerify Bulk File API

Added support for EmailListVerify Bulk File API upload with added `-apibulk emaillistverify` argument. Unfortunately for the below number of emails, the bulk API upload took way longer to process at 45 seconds versus 2.2 seconds for per email verification without `-apibulk emaillistverify` due to remote processing.

```
cat email_verification_log_2024-05-05_17-03-01.log

2024-05-05 17:03:02,607 - INFO - File MIME type: text/plain
2024-05-05 17:03:02,607 - INFO - Request data: {'filename': 'emaillist_20240505170302.txt'}
2024-05-05 17:03:02,607 - INFO - File data: {'file_contents': ('emaillist_20240505170302.txt', <_io.BufferedReader name='emaillist.txt'>, 'text/plain')}
2024-05-05 17:03:03,293 - INFO - File uploaded successfully. File ID: 2400498
2024-05-05 17:03:03,832 - INFO - File processing in progress. Status: progress
2024-05-05 17:03:09,420 - INFO - File processing in progress. Status: progress
2024-05-05 17:03:14,883 - INFO - File processing in progress. Status: progress
2024-05-05 17:03:20,148 - INFO - File processing in progress. Status: progress
2024-05-05 17:03:25,334 - INFO - File processing in progress. Status: progress
2024-05-05 17:03:30,533 - INFO - File processing in progress. Status: progress
2024-05-05 17:03:35,801 - INFO - File processing in progress. Status: progress
2024-05-05 17:03:41,075 - INFO - File processing in progress. Status: progress
2024-05-05 17:03:46,421 - INFO - File processing completed. Retrieving results from: https://files-elv.s3.eu-central-1.amazonaws.com/2024-05/276e5d9b771214ca9e5e6b59f67b481bfa0a2fabc_all.csv
2024-05-05 17:03:46,783 - INFO - Results file downloaded: emaillistverify_results_1714928583.csv
2024-05-05 17:03:46,784 - INFO - Results retrieved successfully. Total lines: 15
```

with `-apibulk emaillistverify` argument

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -api emaillistverify -apikey $elvkey -apibulk emaillistverify -tm all
[
    {
        "email": "user@mailsac.com",
        "status": "disposable",
        "status_code": "",
        "free_email": "yes",
        "disposable_email": "yes"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "dead_server",
        "status_code": "",
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user+to@domain1.com",
        "status": "valid",
        "status_code": "",
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@tempr.email",
        "status": "disposable",
        "status_code": "",
        "free_email": "no",
        "disposable_email": "yes"
    },
    {
        "email": "info@domain2.com",
        "status": "valid",
        "status_code": "",
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "email_disabled",
        "status_code": "",
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "abc@domain1.com",
        "status": "email_disabled",
        "status_code": "",
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "123@domain1.com",
        "status": "email_disabled",
        "status_code": "",
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "pop@domain1.com",
        "status": "email_disabled",
        "status_code": "",
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "pip@domain1.com",
        "status": "email_disabled",
        "status_code": "",
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "valid",
        "status_code": "",
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "email_disabled",
        "status_code": "",
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user@yahoo.com",
        "status": "valid",
        "status_code": "",
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "valid",
        "status_code": "",
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "valid",
        "status_code": "",
        "free_email": "yes",
        "disposable_email": "no"
    }
]
```

## MillionVerifier

Add [MillionVerifier](https://centminmod.com/millionverifier) API support

Manual email test via their dashboard reveals

```csv
"email","quality","result","free","role"
"user@mailsac.com","bad","disposable","no","yes"
"xyz@centmil1.com","bad","invalid","no","no"
"user+to@domain1.com","good","ok","no","no"
"user@tempr.email","bad","disposable","no","yes"
"info@domain2.com","good","ok","no","yes"
"xyz@domain1.com","bad","invalid","no","no"
"abc@domain1.com","bad","invalid","no","yes"
"123@domain1.com","bad","invalid","no","no"
"pop@domain1.com","bad","invalid","no","no"
"pip@domain1.com","bad","invalid","no","no"
"user@gmail.com","good","ok","yes","no"
"op999@gmail.com","bad","invalid","yes","no"
"user@yahoo.com","good","ok","yes","no"
"user1@outlook.com","good","ok","yes","no"
"user2@hotmail.com","good","ok","yes","no"
```

[MillionVerifier](https://centminmod.com/millionverifier) API enabled run `-api millionverifier -apikey_mv $mvkey`

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api millionverifier -apikey_mv $mvkey
[
    {
        "email": "user@mailsac.com",
        "status": "disposable",
        "status_code": null,
        "free_email": false,
        "disposable_email": "yes"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no"
    },
    {
        "email": "user+to@domain1.com",
        "status": "ok",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no"
    },
    {
        "email": "abc@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no"
    },
    {
        "email": "123@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no"
    },
    {
        "email": "pop@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no"
    },
    {
        "email": "pip@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no"
    },
    {
        "email": "user@tempr.email",
        "status": "disposable",
        "status_code": null,
        "free_email": false,
        "disposable_email": "yes"
    },
    {
        "email": "info@domain2.com",
        "status": "ok",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": true,
        "disposable_email": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "invalid",
        "status_code": null,
        "free_email": true,
        "disposable_email": "no"
    },
    {
        "email": "user@yahoo.com",
        "status": "ok",
        "status_code": null,
        "free_email": true,
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "ok",
        "status_code": null,
        "free_email": true,
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": true,
        "disposable_email": "no"
    }
]
```

[MillionVerifier](https://centminmod.com/millionverifier) API enabled run with `-xf -xfdb xenforo -xfprefix xf_` flags

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api millionverifier -apikey_mv $mvkey -xf -xfdb xenforo -xfprefix xf_
[
    {
        "email": "user@mailsac.com",
        "status": "disposable",
        "status_code": null,
        "free_email": false,
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com'; xenforo\""
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com'; xenforo\""
    },
    {
        "email": "user+to@domain1.com",
        "status": "ok",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com'; xenforo\""
    },
    {
        "email": "abc@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com'; xenforo\""
    },
    {
        "email": "123@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com'; xenforo\""
    },
    {
        "email": "pop@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com'; xenforo\""
    },
    {
        "email": "pip@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com'; xenforo\""
    },
    {
        "email": "user@tempr.email",
        "status": "disposable",
        "status_code": null,
        "free_email": false,
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email'; xenforo\""
    },
    {
        "email": "info@domain2.com",
        "status": "ok",
        "status_code": null,
        "free_email": false,
        "disposable_email": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": true,
        "disposable_email": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "invalid",
        "status_code": null,
        "free_email": true,
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com'; xenforo\""
    },
    {
        "email": "user@yahoo.com",
        "status": "ok",
        "status_code": null,
        "free_email": true,
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "ok",
        "status_code": null,
        "free_email": true,
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": true,
        "disposable_email": "no"
    }
]
```

`jq` filterd for Xenforo MySQL queries only

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api millionverifier -apikey_mv $mvkey -xf -xfdb xenforo -xfprefix xf_ | jq -r '.[] | select(.xf_sql) | .xf_sql'

mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com'; xenforo"
```

## CaptainVerify API

Add [CaptainVerify](https://centminmod.com/captainverify) API support. 

CaptainVerify's API has rate limits, as such script needed to add such to it's routines.

> The API is limited to a maximum of 2 simultaneous connections and 50 checks per minute. When integrating the API, make sure your application does not exceed this limit.

### `update_captainverify_rate_limit` Function

The `update_captainverify_rate_limit` function is responsible for managing the rate limiting of requests to the CaptainVerify API. It ensures that the script complies with the API's rate limits of a maximum of 2 simultaneous connections and 50 checks per minute.

#### Purpose

The purpose of the `update_captainverify_rate_limit` function is to coordinate access to the CaptainVerify API across multiple processes and prevent exceeding the API's rate limits. It achieves this by using a shared file (`captainverify_rate_limit.json`) to store and update the rate limiting information.

#### Functionality

The `update_captainverify_rate_limit` function performs the following steps:

1. It takes a `lock_file` parameter, which specifies the path to the file used for storing the rate limiting information.
2. It opens the `lock_file` in read and write mode (`'r+'`) to allow reading from and writing to the file.
3. It acquires an exclusive lock on the file using the `fcntl.flock` function with the `fcntl.LOCK_EX` flag. This ensures that only one process can access and modify the file at a time, preventing race conditions.
4. It reads the existing rate limiting data from the file using `json.load`. The rate limiting data includes the timestamp of the last request (`last_request_time`) and the count of requests made within the current minute (`request_count`).
5. It calculates the elapsed time since the last request by subtracting `last_request_time` from the current time.
6. If the elapsed time is less than 60 seconds (indicating that the current minute has not passed), it increments the `request_count` by 1.
7. If the `request_count` exceeds 50 (the maximum allowed requests per minute), it calculates the remaining time until the current minute completes and sleeps for that duration using `time.sleep`. After sleeping, it updates `last_request_time` to the current time and resets `request_count` to 1.
8. If the elapsed time is greater than or equal to 60 seconds (indicating that a new minute has started), it updates `last_request_time` to the current time and resets `request_count` to 1.
9. It updates the `last_request_time` and `request_count` values in the `data` dictionary.
10. It seeks to the beginning of the file using `file.seek(0)`, writes the updated `data` dictionary to the file using `json.dump`, and truncates any remaining content in the file using `file.truncate()`. This ensures that the file contains only the updated rate limiting data.
11. It releases the exclusive lock on the file using `fcntl.flock` with the `fcntl.LOCK_UN` flag, allowing other processes to access the file.

#### Usage

The `update_captainverify_rate_limit` function is called within the `validate_and_classify` function whenever an email verification request is made to the CaptainVerify API (i.e., when `args.api == 'captainverify'` and `args.test_mode == 'all'`).

By calling `update_captainverify_rate_limit` before making the API request, the script ensures that the rate limiting information is updated and that the API's rate limits are respected across multiple processes.

The `lock_file` parameter specifies the path to the file used for storing the rate limiting information. In the provided code, the file is named `'captainverify_rate_limit.json'` and is initialized in the `main` function.

Manual email test via their dashboard reveals

```csv
email;status;free;disposable;role;ok_for_all;protected;did_you_mean;details
user@mailsac.com;risky;0;1;1;1;0;;low quality
xyz@centmil1.com;invalid;0;0;0;0;0;;smtp error
user+to@domain1.com;ok;0;0;0;0;0;;
user@tempr.email;risky;0;1;1;1;0;;low quality
info@domain2.com;risky;0;0;1;0;0;;low quality
xyz@domain1.com;invalid;0;0;0;0;0;;email error
abc@domain1.com;invalid;0;0;1;0;0;;email error
123@domain1.com;invalid;0;0;1;0;0;;email error
pop@domain1.com;invalid;0;0;0;0;0;;email error
pip@domain1.com;invalid;0;0;0;0;0;;email error
user@gmail.com;ok;1;0;0;0;0;;
op999@gmail.com;invalid;1;0;0;0;0;;email error
user@yahoo.com;unknown;1;0;0;0;0;;
user1@outlook.com;ok;1;0;0;0;0;;
user2@hotmail.com;ok;1;0;0;0;0;;
```

[CaptainVerify](https://centminmod.com/captainverify) API enabled run `-api captainverify -apikey_cv $cvkey`

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api captainverify -apikey_cv $cvkey -xf -xfdb xenforo -xfprefix xf_
[
    {
        "email": "user@mailsac.com",
        "status": "risky",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com'; xenforo\""
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com'; xenforo\""
    },
    {
        "email": "user+to@domain1.com",
        "status": "valid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com'; xenforo\""
    },
    {
        "email": "abc@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com'; xenforo\""
    },
    {
        "email": "123@domain1.com",
        "status": "risky",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com'; xenforo\""
    },
    {
        "email": "pop@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com'; xenforo\""
    },
    {
        "email": "pip@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com'; xenforo\""
    },
    {
        "email": "user@tempr.email",
        "status": "risky",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email'; xenforo\""
    },
    {
        "email": "info@domain2.com",
        "status": "risky",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'info@domain2.com'; xenforo\""
    },
    {
        "email": "user@gmail.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com'; xenforo\""
    },
    {
        "email": "user@yahoo.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@yahoo.com'; xenforo\""
    },
    {
        "email": "user1@outlook.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    }
]
```

`jq` filterd for Xenforo MySQL queries only

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api captainverify -apikey_cv $cvkey -xf -xfdb xenforo -xfprefix xf_ | jq -r '.[] | select(.xf_sql) | .xf_sql'
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'info@domain2.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@yahoo.com'; xenforo"
```

## Proofy API

Add [Proofy.io](https://centminmod.com/proofy) API support

[Proofy.io](https://centminmod.com/proofy) API enabled run `-api proofy -apikey_pf $pkey -apiuser_pf $puser`

```
validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api proofy -apikey_pf $pkey -apiuser_pf $puser -xf -xfdb xenforo -xfprefix xf_
[
    {
        "email": "user@mailsac.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com'; xenforo\""
    },
    {
        "email": "xyz@centmil1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com'; xenforo\""
    },
    {
        "email": "user+to@domain1.com",
        "status": "deliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com'; xenforo\""
    },
    {
        "email": "abc@domain1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com'; xenforo\""
    },
    {
        "email": "123@domain1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com'; xenforo\""
    },
    {
        "email": "pop@domain1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com'; xenforo\""
    },
    {
        "email": "pip@domain1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com'; xenforo\""
    },
    {
        "email": "user@tempr.email",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email'; xenforo\""
    },
    {
        "email": "info@domain2.com",
        "status": "deliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "deliverable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com'; xenforo\""
    },
    {
        "email": "user@yahoo.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@yahoo.com'; xenforo\""
    },
    {
        "email": "user1@outlook.com",
        "status": "deliverable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "deliverable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    }
]
```

Unfortunately, Proofy.io has a stricter max concurrent connection limit so will slow down processing of email verifications. Proofy.io API limits mean email verifications are at least 2x or more slower. As such need to add a `-pf_max_connections` parameter which set to `1` by default when argument not passed on command line like above. But even with `-pf_max_connections 2` Proofy.io API complains and email `status = api_error` occur.

From `email_verification_log_2024-05-05_14-06-36.log`

```
2024-05-05 14:07:08,450 - ERROR - Unexpected API response for user2@hotmail.com: {'error': True, 'message': 'You already use the maximum number of simultaneous connections. Try this request later.'}
2024-05-05 14:07:08,450 - ERROR - Max retries exceeded for user2@hotmail.com. Skipping
```

Testing Proofy.io, ran out of credits from log `email_verification_log_2024-05-05_14-20-50.log`

```
2024-05-05 14:21:35,810 - ERROR - Unexpected API response for user2@hotmail.com: {'error': True, 'message': "You don't have checks. Check your balance."}
2024-05-05 14:21:46,461 - ERROR - Max retries exceeded for user2@hotmail.com. Skipping.
```

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api proofy -apikey_pf $pkey -apiuser_pf $puser -xf -xfdb xenforo -xfprefix xf_ -pf_max_connections 2
[
    {
        "email": "user@mailsac.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    },
    {
        "email": "user+to@domain1.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    },
    {
        "email": "xyz@domain1.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    },
    {
        "email": "abc@domain1.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    },
    {
        "email": "123@domain1.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    },
    {
        "email": "pop@domain1.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    },
    {
        "email": "pip@domain1.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    },
    {
        "email": "user@tempr.email",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    },
    {
        "email": "info@domain2.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    },
    {
        "email": "user@gmail.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    },
    {
        "email": "op999@gmail.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    },
    {
        "email": "user@yahoo.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    },
    {
        "email": "user1@outlook.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    },
    {
        "email": "user2@hotmail.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "unknown"
    }
]
```

`jq` filterd for Xenforo MySQL queries only

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api proofy -apikey_pf $pkey -apiuser_pf $puser -xf -xfdb xenforo -xfprefix xf_ | jq -r '.[] | select(.xf_sql) | .xf_sql'
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'info@domain2.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@yahoo.com'; xenforo"
```

## MyEmailVerifier API

Add [MyEmailVerifier](https://centminmod.com/myemailverifier) API support

[MyEmailVerifier](https://centminmod.com/myemailverifier) API enabled run `-api myemailverifier -apikey_mev $mevkey`

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -api myemailverifier -apikey_mev $mevkey -tm all
[
    {
        "email": "user@mailsac.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "yes"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user+to@domain1.com",
        "status": "valid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "abc@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "123@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "pop@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "pip@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@tempr.email",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes"
    },
    {
        "email": "info@domain2.com",
        "status": "valid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user@yahoo.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    }
]
```

`jq` filterd for Xenforo MySQL queries only

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -api myemailverifier -apikey_mev $mevkey -tm all -xf -xfdb xenforo -xfprefix xf_ | jq -r '.[] | select(.xf_sql) | .xf_sql'

mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email'; xenforo"
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com'; xenforo"
```