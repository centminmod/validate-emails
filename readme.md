# Email Validation Script

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Usage](#usage)
- [Output](#output)
- [Logging](#logging)
- [Configuration](#configuration)
  - [`validate_emails.ini` config file](#validate_emailsini-config-file)
  - [S3 Storage Support](#s3-storage-support)
  - [-smtp ses](#-smtp-ses)
  - [-smtp rotate](#-smtp-rotate)
  - [-smtp generic](#-smtp-generic)
- [Customization](#customization)
- [Troubleshooting](#troubleshooting)
- [Example Usage](#example-usage) 
  - [Xenforo](#xenforo)
  - [Xenforo Email Bounce Log](#xenforo-email-bounce-log)
- [API Support](#api-support)
  - [API Usage Commands](#api-usage-commands)
  - [Personal Experience](#personal-experience)
  - [Email Verification Provider Comparison Costs](#email-verification-provider-comparison-costs)
  - [Email Verification Provider API Speed & Rate Limits](#email-verification-provider-api-speed--rate-limits)
  - [Email Verification Results Table Compare](#email-verification-results-table-compare)
  - [EmailListVerify](#emaillistverify)
  - [EmailListVerify Bulk File API](#emaillistverify-bulk-file-api)
  - [MillionVerifier](#millionverifier)
  - [MillionVerifier Bulk File API](#millionverifier-bulk-file-api)
  - [MillionVerifier Bulk API Differences](#millionverifier-bulk-api-differences)
  - [CaptainVerify API](#captainverify-api)
  - [Proofy API](#proofy-api)
  - [MyEmailVerifier API](#myemailverifier-api)
  - [Zerobounce API](#zerobounce-api),
  - [Reoon API](#reoon-api)
  - [Bouncify API](#bouncify-api)
  - [Bounceless API](#bounceless-api)
  - [API Merge](#api-merge)
    - [API Merge Filters](#api-merge-filters)
- [Cloudflare HTTP Forward Proxy Cache With KV Storage](#cloudflare-http-forward-proxy-cache-with-kv-storage)
  - [ZeroBounce Cloudflare Cache Support](#zerobounce-cloudflare-cache-support)
  - [Cloudflare Cache Purge Support](#cloudflare-cache-purge-support)
  - [EmailListVeirfy Bulk File API Cloudflare Cache Support](#emaillistveirfy-bulk-file-api-cloudflare-cache-support)
  - [EmailListVerify API Check Times: Regular vs Cached](#emaillistverify-api-check-times-regular-vs-cached)
- [PHP Wrapper](#php-wrapper)
  - [PHP Wrapper With Cloudflare Cache And S3 Store Support](#php-wrapper-with-cloudflare-cache-and-s3-store-support)

## Overview
The `validate_emails.py` is a Python-based tool for email verification and email validation that allows you to classify your email addresses' status using syntax, DNS, and SMTP (Simple Mail Transfer Protocol) and other checks and 3rd party APIs. Using the script's returned status classifications, you can then clean or scrub your email lists. This can be done self-hosted locally on a server or via the supported [commercial email verification service APIs](#api-support). The script's [API Merge support](#api-merge) also allows you to combine 2 API email verification providers results into one JSON formated output for double verification checks. The script provides a convenient way to verify the existence and deliverability of email addresses, helping you maintain a clean and accurate email list.

The script offers specific support for [Xenforo](#xenforo) forum member email list verification through dedicated Xenforo argument flags. These flags enable you to mark invalid Xenforo forum member emails and move them to a `bounce_email` status, effectively disabling Xenforo email sending to those members without actually deleting the Xenforo member account. You can then setup a Xenforo forum wide notice targetting `bounce_email` status users - prompting them to update their email addresses.

To reduce potential 3rd party email verification API costs, this script also supports [Cloudflare HTTP Forward Proxy Cache With KV Storage](#cloudflare-http-forward-proxy-cache-with-kv-storage) for both per email check and [bulk file](#emaillistveirfy-bulk-file-api-cloudflare-cache-support) API check results to be temporarily cached and return the email verification status codes at the Cloudflare CDN and Cloudflare Worker KV storage level.

Email verification results can also be optionally saved to [Amazon AWS S3 and Cloudflare R2 object storage](#s3-storage-support) for long term storage and retrieval.

The `validate_emails.py` email validation script was written by George Liu (eva2000) for his paid consulting clients usage. The below is public documentation for the script.

## Features
- Validates email addresses using syntax, DNS and SMTP checks
- Validates `-f` from email address's SPF, DKIM, DMARC records and logs them for troubleshooting mail deliverability
- Optionally save your email verification results to [S3 object storage providers - Cloudflare R2 or Amazon S3](#s3-storage-support)
- Support local self-hosted email verification + [API support](#api-support) for:
  - [EmailListVerify](https://centminmod.com/emaillistverify) [[example](#emaillistverify-1), [bulk API](#emaillistverify-bulk-file-api)] 
  - [MillionVerifier](https://centminmod.com/millionverifier) [[example](#millionverifier), [bulk API](#millionverifier-bulk-file-api)]
  - [MyEmailVerifier](https://centminmod.com/myemailverifier) [[example](#myemailverifier-api)]
  - [CaptainVerify](https://centminmod.com/captainverify) [[example](#captainverify-api)]
  - [Proofy.io](https://centminmod.com/proofy) [[example](#proofy-api)]
  - [Zerobounce](https://centminmod.com/zerobounce) [[example](#zerobounce-api)]
  - [Reoon](https://centminmod.com/reoon) [[example](#reoon-api)]
  - [Bouncify](https://centminmod.com/bouncify) [[example](#bouncify-api)]
  - [Bounceless](https://centminmod.com/bounceless) [[example](#bounceless-api)]
  - [API Merge support](#api-merge) via `-apimerge` argument to merge [EmailListVerify](https://centminmod.com/emaillistverify) + [MillionVerifier](https://centminmod.com/millionverifier) API results together for more accurate email verification results.
- Supports [Cloudflare HTTP Forward Proxy Cache With KV Storage](#cloudflare-http-forward-proxy-cache-with-kv-storage) for [EmailListVerify](https://centminmod.com/emaillistverify) per email check API
- Classifies email addresses into various categories based on the syntax, DNS, and SMTP response
- Supports concurrent processing for faster validation of multiple email addresses
- Provides detailed logging for tracking the validation process
- Allows customization of delay between requests to respect email server limitations
- Supports input of email addresses via command-line arguments or a file
- Identifies disposable email addresses and free domain name provider addresses
- Checks email addresses against custom blacklists and whitelists
- Supports different test modes for syntax, DNS, SMTP, and disposable email checks
- Configurable SMTP port and TLS/SSL support
- Supports SMTP profiles. However, using SMTP relay profiles won't get accurate SMTP checks. Locally ran server SMTP checks are more accurate.
- Supports different DNS lookup methods: asyncio, concurrent, and sequential
- Supports different processing modes: thread and asyncio
- [Xenforo](#xenforo) support. Generates SQL queries for updating user status `user_state` in XenForo forum based email validation results. Allowing you to clean up your Xenforo user database's email addresses by disabling email sending to those specific bad email addresses.

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
                             [-wf WORKER_FACTOR]
                             [-api {emaillistverify,millionverifier,captainverify,proofy,myemailverifier,zerobounce,reoon,bouncify,bounceless}]
                             [-apikey EMAILLISTVERIFY_API_KEY] [-apikey_mv MILLIONVERIFIER_API_KEY]
                             [-apibulk {emaillistverify,millionverifier,proofy,bounceless}] [-apikey_cv CAPTAINVERIFY_API_KEY]
                             [-apikey_pf PROOFY_API_KEY] [-apiuser_pf PROOFY_USER_ID] [-pf_max_connections PROOFY_MAX_CONNECTIONS]
                             [-pf_batchsize PROOFY_BATCH_SIZE] [-apikey_mev MYEMAILVERIFIER_API_KEY] [-apikey_zb ZEROBOUNCE_API_KEY]
                             [-apikey_rn REOON_API_KEY] [-reoon_mode {quick,power}] [-apikey_bf BOUNCIFY_API_KEY]
                             [-apikey_bl BOUNCELESS_API_KEY] [-mev_max_connections MEV_MAX_CONNECTIONS] [-apimerge]
                             [-apicache {emaillistverify,zerobounce}] [-apicachettl APICACHETTL] [-apicachecheck {count,list,purge}]
                             [-apicache-purge] [-store {r2,s3}] [-store-list]
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
      - `zerobounce`: Use the Zerobounce.net API.
      - `reoon`: Use the Zerobounce.net API.
      - `bouncify`: Use the Bouncify API.
      - `bounceless`: Use the Bounceless API.
  - `-apimerge`, `--api_merge` (optional):
    - Description: Merge and combine `emaillistverify` or `millionverifier` API results into one result
  - `-apibulk`, `--api_bulk` (optional):
    - Description: Use `emaillistverify` or `millionverifier` values for Bulk file API method.
  - `-apikey`, `--emaillistverify_api_key` (optional):
    - Description: The API key for the EmailListVerify service.
  - `-apikey_mv`, `--millionverifier_api_key` (optional):
    - Description: The API key for the MillionVerifier service.
  - `-apikey_mev`, `--myemailverifier-api-key` (optional):
    - Description: The API key for the MyEmailVerifier service.
  - `-apikey_cv`, `--captainverify_api_key` (optional):
    - Description: The API key for the CaptainVerify service.
  - `-apikey_zb`, `--zerobounce_api_key` (optional):
    - Description: The API key for the Zerobounce.net service.
  - `-apikey_rn`, `--reoon_api_key` (optional):
    - Description: The API key for the Reoon service.
  - `-reoon_mode`, `--reoon_mode`
    - Description: Reoon verification mode `quick` or `power`
  - `-apikey_bf`, `--bouncify_api_key`
    - Description: The API key for the Bouncify service.
  - `-apikey_bl`, `--bounceless_api_key`
    - Description: The API key for the Bounceless service.
  - `-apikey_pf`, `--proofy_api_key` (optional):
    - Description: The API key for the Proofy service.
  - `-apiuser_pf`, `--proofy_user_id` (optional):
    - Description: The Proofy userid.
  - `-pf_max_connections` (optional):
    - Description: Maximum number of concurrent connections for the Proofy.io API (default: 1)
  - `-mev_max_connections` (optional):
    - Description: Maximum number of concurrent connections for the MyEmailVerifier API (default: 1)
  - `-apicache`, `--api_cache` (optional):
    - Description: Set the appropriate API's Cloudflare Worker KV cacheKey prefix. Available options are:
      - `emaillistverify`: Use with the EmailListVerify API.
  - `-apicachettl` (optional):
    - Description:  this sets the cache TTL duration in seconds for how long Cloudflare CDN/KV stores in cache (default: 300 seconds)
  - `-apicachecheck` (optional):
    - Description:  operates when `-apicachettl` is set and takes `count` or `list` or `purge` options to query the Cloudflare KV storage cache to count number of cached entries or list the entries themselves
  - `-apicache-purge` (optional):
    - Description:  purges Cloudflare CDN/KV cache when `-apicachecheck` set to `purge` option

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
  - `invalid`: The email address has an invalid format.
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

### `validate_emails.ini` config file

Add `validate_emails.ini` config file support so Cloudflare Worker KV caching endpoint url can be defined outside of the script. If `validate_emails.ini` doesn't exist, you'll get this message

```
./validate_emails.py 
Error: 'api_url' setting not found in 'validate_emails.ini' file.
Please create the 'validate_emails.ini' file in the same directory as the script and add the 'api_url' setting.
```

`validate_emails.ini` contents setting `api_url`

```
[settings]
api_url=http=https://your_cf_worker.com
```

### S3 Storage Support

Commercial email verification providers usually only store your file based uploaded or bulk file API uploaded files for a defined duration i.e. 15 to 30 days before they are deleted. And per email check API results are usually not stored at all. So if you need to store your per email check or bulk file API email verification results for longer, the `validate_emails.py` script now supports saving your results to S3 object storage providers - Cloudflare R2 or Amazon AWS S3.

Add optional Cloudflare R2 S3 object storage or Amazon AWS S3 object storage which will allow you to save your `validate_emails.py` ran JSON output in externel Cloudflare R2 or Amazon AWS S3 object storage buckets via `validate_emails.ini` defined:

For Cloudflare R2

```
[r2]
endpoint_url = https://your-account-id.r2.cloudflarestorage.com
aws_access_key_id = your-r2-access-key-id
aws_secret_access_key = your-r2-secret-access-key
bucket_name = your-r2-bucket-name
```

For Amazon AWS S3

```
[s3]
endpoint_url = https://your-s3-endpoint-url
aws_access_key_id = your-s3-access-key-id
aws_secret_access_key = your-s3-secret-access-key
bucket_name = your-s3-bucket-name
```

Below example to send `validate_emails.py` script results to Cloudflare R2 S3 object storage via `-store r2` argument. Using [EmailListVerify](https://centminmod.com/emaillistverify) per email check API `-api emaillistverify -apikey $elvkey` + Cloudflare cached for 120 seconds `-apicache emaillistverify -apicachettl 120`

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com,hnyfmw2@canadlan-drugs.com,hnyfmw3@canadlan-drugs.com -api emaillistverify -apikey $elvkey -apicache emaillistverify -apicachettl 120 -tm all -store r2

Output stored successfully in R2: emailapi-emaillistverify-cached/output_20240511051940.json
[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "hnyfmw2@canadlan-drugs.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "hnyfmw3@canadlan-drugs.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    }
]

real    0m1.663s
user    0m0.391s
sys     0m0.039s
```

`validate_emails.py` script's Cloudflare R2 saved `emailapi-emaillistverify-cached/output_20240511051940.json` log contents

```
cat emailapi-emaillistverify-cached/output_20240511051940.json

[{"email": "hnyfmw@canadlan-drugs.com", "status": "unknown", "status_code": null, "free_email": "no", "disposable_email": "no"}, {"email": "hnyfmw2@canadlan-drugs.com", "status": "unknown", "status_code": null, "free_email": "no", "disposable_email": "no"}, {"email": "hnyfmw3@canadlan-drugs.com", "status": "unknown", "status_code": null, "free_email": "no", "disposable_email": "no"}]
```

`validate_emails.py` run log inspection

```
cat $(ls -Art | tail -3 | grep 'email_verification')                                             
2024-05-11 05:14:23,074 - INFO - Checking cache for email: hnyfmw@canadlan-drugs.com
2024-05-11 05:14:23,075 - INFO - Checking cache for email: hnyfmw2@canadlan-drugs.com
2024-05-11 05:14:23,075 - INFO - Checking cache for email: hnyfmw3@canadlan-drugs.com
2024-05-11 05:14:25,206 - INFO - Cache result: unknown
2024-05-11 05:14:25,966 - INFO - Cache result: unknown
2024-05-11 05:14:26,092 - INFO - Cache result: unknown
```

Non-cached [EmailListVerify](https://centminmod.com/emaillistverify) per email check API `-api emaillistverify -apikey $elvkey` run

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com,hnyfmw2@canadlan-drugs.com,hnyfmw3@canadlan-drugs.com -api emaillistverify -apikey $elvkey -tm all -store r2

Output stored successfully in R2: emailapi-emaillistverify/output_20240511055822.json
[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "hnyfmw2@canadlan-drugs.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "hnyfmw3@canadlan-drugs.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    }
]

real    0m10.612s
user    0m0.541s
sys     0m0.033s
```

`validate_emails.py` script's Cloudflare R2 saved `emailapi-emaillistverify/output_20240511055822.json` log contents

```
cat emailapi-emaillistverify/output_20240511055822.json

[{"email": "hnyfmw@canadlan-drugs.com", "status": "unknown", "status_code": null, "free_email": "no", "disposable_email": "no"}, {"email": "hnyfmw2@canadlan-drugs.com", "status": "unknown", "status_code": null, "free_email": "no", "disposable_email": "no"}, {"email": "hnyfmw3@canadlan-drugs.com", "status": "unknown", "status_code": null, "free_email": "no", "disposable_email": "no"}]
```

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

However, using SMTP relay profiles won't get accurate SMTP checks. Locally ran server SMTP checks are more accurate.

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

However, using SMTP relay profiles won't get accurate SMTP checks. Locally ran server SMTP checks are more accurate.

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

However, using SMTP relay profiles won't get accurate SMTP checks. Locally ran server SMTP checks are more accurate.

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

Xenforo arguments mode for `-xf -xfdb xenforo -xfprefix xf_` has ben updated to output

- `xf_sql` for MySQL query you can run on SSH command line. The command's double quotes are escaped `\"` so you remove the backslash manually, or use below outlined `jq` tool to automatically remove it
- `xf_sql_batch` for MySQL query run in MySQL client, phpmyadmin etc
- `xf_sql_user` for MySQL query you can run on SSH command line to look up Xenforo user details for that email address. The command's double quotes are escaped `\"` so you remove the backslash manually, or use below outlined `jq` tool to automatically remove it

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -xf -xfdb xenforo -xfprefix xf_
[
    {
        "email": "user@mailsac.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';\" xenforo",
        "xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';",
        "xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'user@mailsac.com'\\G\" xenforo"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid",
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
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';\" xenforo",
        "xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';",
        "xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'xyz@domain1.com'\\G\" xenforo"
    },
    {
        "email": "abc@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';\" xenforo",
        "xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';",
        "xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'abc@domain1.com'\\G\" xenforo"
    },
    {
        "email": "123@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';\" xenforo",
        "xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';",
        "xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = '123@domain1.com'\\G\" xenforo"
    },
    {
        "email": "pop@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';\" xenforo",
        "xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';",
        "xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'pop@domain1.com'\\G\" xenforo"
    },
    {
        "email": "pip@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';\" xenforo",
        "xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';",
        "xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'pip@domain1.com'\\G\" xenforo"
    },
    {
        "email": "user@tempr.email",
        "status": "ok",
        "status_code": 250,
        "free_email": "no",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';\" xenforo",
        "xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';",
        "xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'user@tempr.email'\\G\" xenforo"
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
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';\" xenforo",
        "xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';",
        "xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'op999@gmail.com'\\G\" xenforo"
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

Use `jq` tool to filter for `xf_sql` only

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -xf -xfdb xenforo -xfprefix xf_ | jq -r '.[] | select(.xf_sql) | .xf_sql'
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';" xenforo
```

Use `jq` tool to filter for `xf_sql_batch` only. You can pipe or place this output into a `update.sql` file and import into your Xenforo MySQL database to batch update the user's `user_state`

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -xf -xfdb xenforo -xfprefix xf_ | jq -r '.[] | select(.xf_sql_batch) | .xf_sql_batch'
UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';
UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';
UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';
UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';
UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';
UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';
UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';
UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';
```

Use `jq` tool to filter for `xf_sql_user` only. This allows you to run on SSH command line the Xenforo database lookup for the Xenforo user details for the specific email address

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -xf -xfdb xenforo -xfprefix xf_ | jq -r '.[] | select(.xf_sql_user) | .xf_sql_user'
mysql -e "SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'user@mailsac.com'\G" xenforo
mysql -e "SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'xyz@domain1.com'\G" xenforo
mysql -e "SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'abc@domain1.com'\G" xenforo
mysql -e "SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = '123@domain1.com'\G" xenforo
mysql -e "SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'pop@domain1.com'\G" xenforo
mysql -e "SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'pip@domain1.com'\G" xenforo
mysql -e "SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'user@tempr.email'\G" xenforo
mysql -e "SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'op999@gmail.com'\G" xenforo
```

Example running one of these commands for `pop@domain1.com` on server where Xenforo is installed. The `user_state` would either be `valid` prior to running above `UPDATE` command or `email_bounce` after running `UPDATE` command.

```
mysql -e "SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'pop@domain1.com'\G" xenforo
*************************** 1. row ***************************
            user_id: 11
           username: pop
              email: pop@domain1.com
      user_group_id: 2
secondary_group_ids: 3,4,6,8
      message_count: 191817
      register_date: 1400868747
      last_activity: 1715011284
         user_state: email_bounce
       is_moderator: 1
           is_admin: 1
          is_banned: 0
```

`register_date` date

```
date -d @1400868747
Fri May 23 18:12:27 UTC 2014
```

`last_activity` date

```
date -d @1715011284
Mon May  6 16:01:24 UTC 2024
```

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -xf -xfdb xenforo -xfprefix xf_ | jq 'map({ status: .status }) | group_by(.status) | map({ status: .[0].status, count: length })'

[
  {
    "status": "invalid",
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

### Xenforo Email Bounce Log

Example lookup for Xenforo forum's email bounce log via my custom `xf_bounce_log.py` for email address `hnyfmw@canadlan-drugs.com` that is bouncing emails. And using `validate_emails.py` script's local and API to lookup email address status.

```
./xf_bounce_log.py -d $xfdb -n 10 -s desc | jq '.[] | select(.recipient == "hnyfmw@canadlan-drugs.com") | {bounce_id, message_type, action_taken, user_id, recipient, status_code, diagnostic_info, "Delivered-To": .raw_message["Delivered-To:"], "Delivery-date": .raw_message["Delivery-date:"], "Delivery-date": .raw_message["Delivery-date:"], "Subject": .raw_message["Subject:"]}'

{
  "bounce_id": 203,
  "message_type": "bounce",
  "action_taken": "soft",
  "user_id": 122136,
  "recipient": "hnyfmw@canadlan-drugs.com",
  "status_code": "4.4.7",
  "diagnostic_info": " 550 4.4.7 Message expired: unable to deliver in 840 minutes.<421 4.4.0 Unable to lookup DNS for canadlan-drugs.com>",
  "Delivered-To": "bouncer@domain1.com",
  "Delivery-date": "Fri, 26 Apr 2024 15:44:06 +0000",
  "Subject": "Delivery Status Notification (Failure)"
}
```

`validate_emails.py` self-hosted local email verification check for syntax, DNS and SMTP checks for `hnyfmw@canadlan-drugs.com`

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all         
[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "no"
    }
]

real    0m0.932s
user    0m0.428s
sys     0m0.025s
```

`validate_emails.py` using external [EmailListVerify](https://centminmod.com/emaillistverify) API email verification check

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api emaillistverify -apikey $elvkey
[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    }
]

real    0m2.626s
user    0m0.461s
sys     0m0.023s
```

`validate_emails.py` using external [MillionVerifier](https://centminmod.com/millionverifier) API email verification check

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api millionverifier -apikey_mv $mvkey
[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false
    }
]

real    0m1.142s
user    0m0.455s
sys     0m0.024s
```

`validate_emails.py` using external [MyEmailVerifier](https://centminmod.com/myemailverifier) API email verification check

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api myemailverifier -apikey_mev $mevkey
[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    }
]

real    0m1.823s
user    0m0.463s
sys     0m0.019s
```

`validate_emails.py` using external [CaptainVerify](https://centminmod.com/captainverify) API email verification check

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api captainverify -apikey_cv $cvkey
[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    }
]

real    0m25.264s
user    0m0.457s
sys     0m0.022s
```

Unfortunately, I ran out of credits to test with [Proofy.io](https://centminmod.com/proofy).

`validate_emails.py` using external [Zerobounce](https://centminmod.com/zerobounce) API enabled run `-api zerobounce -apikey_zb $zbkey -tm all` with specified email address `-e hnyfmw@canadlan-drugs.com`. The `status`, `sub_status` and `free_email_api` JSON fields are from API and `free_email` and `disposable_email` JSON fields are from local script database checks.

```
python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api zerobounce -apikey_zb $zbkey -tm all

[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "invalid",
        "sub_status": "no_dns_entries",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no"
    }
]
```

`validate_emails.py` using external [Reoon](https://centminmod.com/reoon) API enabled run `-api reoon -apikey_rn $reokey -tm all` with specified email address `-e hnyfmw@canadlan-drugs.com`. The `status`, `role_account`, `mx_accepts_mail`, `spamtrap`, `mx_records`, `overall_score`, `safe_to_send`, `can_connect_smtp`, `inbox_full`, `catch_all`, `deliverable`, `disabled` JSON field is from API and `free_email` and `disposable_email` JSON fields are from local script database checks.

Reoon has 2 modes for single email verification API which can be set via `-reoon_mode` to a value of either `quick` or `power`. The default mode without `-reoon_mode` being set is `quick`.

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api reoon -apikey_rn $reokey

[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "role_account": "no",
        "mx_accepts_mail": "no",
        "spamtrap": "no",
        "mx_records": null,
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    }
]

real    0m3.748s
user    0m0.358s
sys     0m0.028s
```

`validate_emails.py` using external [Bouncify](https://centminmod.com/bouncify) API enabled run `-api bouncify -apikey_bf $bfkey -tm all` with specified email address `-e hnyfmw@canadlan-drugs.com`. The `status`, `free_email_api`, `disposable_email_api`, `role_api`, and `spamtrap_api` JSON field are from API and `free_email` and `disposable_email` JSON fields are from local script database checks.

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api bouncify -apikey_bf $bfkey
[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    }
]

real    0m7.900s
user    0m0.357s
sys     0m0.030s
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
- `spamtrap`  The email address is maintained by an ISP or a third party,which neither clicks nor opens emails
- `invalid_mx` An undocumentated status value that isn't in their documentation. As the name implies, invalid MX DNS records

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

mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';" xenforo
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
        "status": "invalid",
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
        "status": "invalid",
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

In additional to local self-hosted email verification, the script now has added support for the following external Email cleaning service APIs - [EmailListVerify](https://centminmod.com/emaillistverify), [MillionVerifier](https://centminmod.com/millionverifier), [MyEmailVerifier](https://centminmod.com/myemailverifier), [CaptainVerify](https://centminmod.com/captainverify), [Proofy.io](https://centminmod.com/proofy), [Zerobounce](https://centminmod.com/zerobounce), [Reoon](https://centminmod.com/reoon), [Bouncify](https://centminmod.com/bouncify), [Bounceless](https://centminmod.com/bounceless). Links to services maybe affiliate links. If you found this information useful ;)

Updated: Added [API Merge support](#api-merge) via `-apimerge` argument to merge [EmailListVerify](https://centminmod.com/emaillistverify) + [MillionVerifier](https://centminmod.com/millionverifier) API results together for more accurate email verification results.

## API Usage Commands

`validate_emails.py` supports passing individual email's comma separated via `-e` flag i.e. `-e user@domain1.com,user@domain2.com` or passing `-l` flag for a text file with list of email addresses one per line via -`l emaillist.txt`. Both methods use respetive provider's per email verification APIs. Only some providers have support in the script for bulk email API - which is currently [EmailListVerify](https://centminmod.com/emaillistverify) and [MillionVerifier](https://centminmod.com/millionverifier) via `-apibulk` flag i.e. `-l emaillist.txt -apibulk emaillistverify` or `-l emaillist.txt -apibuilk millionverifier`.

You can see a full list and explanation of all argument flags supported at [here](#usage).

The `-api` flag determines which provider you use along with their respective `-apikey*` flag.

[EmailListVerify](https://centminmod.com/emaillistverify)

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api emaillistverify -apikey $elvkey
```

[MillionVerifier](https://centminmod.com/millionverifier)

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api millionverifier -apikey_mv $mvkey
```

[CaptainVerify](https://centminmod.com/captainverify)

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api captainverify -apikey_cv $cvkey
```

[Proofy.io](https://centminmod.com/proofy)

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api proofy -apikey_pf $pkey -apiuser_pf $puser
```

[MyEmailVerifier](https://centminmod.com/myemailverifier)

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api myemailverifier -apikey_mev $mevkey
```

[Zerobounce](https://centminmod.com/zerobounce)

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api zerobounce -apikey_zb $zbkey
```

[Reoon](https://centminmod.com/reoon)

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api reoon -apikey_rn $reokey
```

[Bouncify](https://centminmod.com/bouncify)

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api bouncify -apikey_bf $bfkey
```

[Bounceless](https://centminmod.com/bounceless)

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api bounceless -apikey_bf $blkey
```

**Notes:**

- Some providers have enabled optional [Cloudflare HTTP Forward Proxy Cache With KV Storage](#cloudflare-http-forward-proxy-cache-with-kv-storage)
- All providers support optional `-store` flag to save email verification results to remote [S3 storage](#s3-storage-support) i.e. Amazon AWS S3 or Cloudflare R2 object storage buckets
- There's also work on a [PHP Wrapper](#php-wrapper) script.

## Personal Experience

Personal experience with all commercial email verification providers:

- Disclaimer: I've already been using EmailListVerify since 2015 and Proofy.io since 2022. While the rest of the mentioned providers are new experiences for me.
- EmailListVerify and MillionVerifier while being cheaper than the others seem to be better for the following:
  - API documentation
  - Less restrictive on API connection and rate limits. Meaning if you are doing per email API checks for many email addresses, the speed of completion will be faster. Though if you're doing many email address checks, you'd want to use their respective bulk email API end points to upload a single text file for processing.
  - For bulk API speed though, MillionVerifier is much faster than EmailListVerify. Even MillionVerifier's per email check API speed can be as low as 100ms for check and has a rate limit of [400 emails/second](https://help.millionverifier.com/email-verification-api/real-time-api) per unqiue IP address. For the sample 15 email addresses tested below, MillionVerifier bulk API took ~7 seconds, EmailListVerify bulk API took ~45 seconds. Compared to per email address verification checks, both taking between 2.2 to 3.3 seconds. EmailListVerify seems to have much more detailed status classifications (see below) compared to ther others so more processing is done on their end.
- MillionVerifier has email verification speed information [here](https://help.millionverifier.com/bulk-email-verification/email-verification-speed)
- MillionVerifier allow for a [maximum 2 simultaneous bulk file API uploads at a time](https://help.millionverifier.com/bulk-email-verification/verify-multiple-files-at-the-same-time) and max size of files uploaded are [1 million emails per file or 100MB size](https://help.millionverifier.com/bulk-email-verification/upload-emails-for-verification). If each of the files contains more than 1000 emails, they will verify a maximum of 2 files at a time.
- MillionVerifier API logging for billing is the mosted detailed with historical running balances. They also show per API call credit usage balance details and even list in the logs refunded credits for bulk API file uploaded emails classified as 'risky' (`catch_all` or `unknown`) https://help.millionverifier.com/payments-credits/refund-for-risky-emails. AFAIK, the other providers don't refund any credits that I can see. However, on below sample 15 email addresses tested, I always got 1 refunded credit so it applies to one email address which is a known valid email `user@yahoo.com` which is classed as `unknown` in bulk API but classed as `ok` in per email verification API. Seems to be a bug in their bulk API then as the refunds only apply to bulk API and not per email verification checks due to differences in classifications in bulk API vs per email verification API. 

  I reached out to MillionVerifier chat support which was initially handled via Milly their AI chat bot which later referred me to support. They emailed me back saying:

  > We're glad you reached out to us about this issue, and we're here to help.
  > The discrepancy you're seeing in the results is likely because we were unable to connect to the server during the verification process, leading to an "Unknown" result. However, for the single API, the connection went through smoothly, allowing us to verify the email without any problems. An "Unknown" result simply means that we couldn't determine the existence of the email at the time of verification.
  > If you have any more questions, queries, or issues, we're more than happy to assist.

  I tried a few attempts at bulk API for the same list of 15 emails, and `user@yahoo.com` is always marked as status = `unknown` and never anything different though? It would be hard to differentiate status classifications if it's due connection issues if they're lumped into other emails in unknown label. Maybe would be better to have a separate classification for connection issues so we can differentiate as such. For example, EmailListVerify has 18 different status classifications including for connection related issues.

  single email API check for `user@yahoo.com` returns `ok`
  ```
  python validate_emails.py -f user@domain1.com -e user@yahoo.com -api millionverifier -apikey_mv $mvkey -tm all
  [
      {
          "email": "user@yahoo.com",
          "status": "ok",
          "status_code": null,
          "free_email": "yes",
          "disposable_email": "no",
          "free_email_api": true,
          "role_api": false
      }
  ]
  ```

  bulk API upload check excerpt for `user@yahoo.com` returns `unknown`

  ```
  python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api millionverifier -apikey_mv $mvkey -apibulk millionverifier
  [
   
      {
          "email": "user@yahoo.com",
          "status": "unknown",
          "free_email": "yes",
          "disposable_email": "no",
          "free_email_api": "yes",
          "role_api": "no"
      },

  ]
  ```
  As such you can't 100% rely on the status output to do tasks like updating Xenforo user's `user_state` status to stop sending emails to them without further verification for such emails. For now, I've updated my `validate_emails.py` script for MillionVerifier bulk API and per email check API results, to not list [Xenforo SQL queries](#xenforo) for `unknown` status results and only list [Xenforo SQL queries](#xenforo) for `invalid` and `disposable` status emails. Same can be said for other providers, probably need to really double check your results if you're relying on the results for important tasks. You can filter MillionVerifier's `unknown` status emails and feed them into another commercial provider's API to double check i.e. EmailListVerify or use script's self-hosted local email check. Given cheaper MillionVerifier pricing, it might be more economical to do it this way?

  MillionVerifier bulk API filter `-api millionverifier -apikey_mv $mvkey -apibulk millionverifier` filter using `jq` for `unknown` status emails piped into text file `results-millionverifier-bulk-api-unknown-only.txt`

  ```
  python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api millionverifier -apikey_mv $mvkey -apibulk millionverifier | jq '.[] | select(.status == "unknown")' 2>&1 > results-millionverifier-bulk-api-unknown-only.txt
  ```

  The `results-millionverifier-bulk-api-unknown-only.txt` contents will show all MillionVerifier bulk API returned `unknown` status results.

  ```
  cat results-millionverifier-bulk-api-unknown-only.txt                                            
  {
    "email": "user@yahoo.com",
    "status": "unknown",
    "free_email": "yes",
    "disposable_email": "no",
    "free_email_api": "yes",
    "role_api": "no"
  }
  ```

  Using same `results-millionverifier-bulk-api-unknown-only.txt` file, and `jq` just filter out the email addresses into a new `results-millionverifier-bulk-api-unknown-only-emails.txt` file


  ```
  cat results-millionverifier-bulk-api-unknown-only.txt | jq -r '.email' | tee results-millionverifier-bulk-api-unknown-only-emails.txt
  user@yahoo.com
  ```

  Then use EmailListVerify bulk API to verify the filtered MillionVerifier `unknown` status list filtered file `results-millionverifier-bulk-api-unknown-only-emails.txt` and double check the status which confirms it's actually a `valid` email.

  ```
  python validate_emails.py -f user@domain1.com -l results-millionverifier-bulk-api-unknown-only-emails.txt -tm all -api emaillistverify -apikey $elvkey -apibulk emaillistverify

  [
      {
          "email": "user@yahoo.com",
          "status": "valid",
          "status_code": "",
          "free_email": "yes",
          "disposable_email": "no"
      }
  ]
  ```

  Or EmailListVerify per email verification API check

  ```
  ./validate_emails.py -f user@domain1.com -e user@yahoo.com -tm all -api emaillistverify -apikey $elvkey -tm all
  [
      {
          "email": "user@yahoo.com",
          "status": "valid",
          "status_code": null,
          "free_email": "yes",
          "disposable_email": "no"
      }
  ]
  ```

  Or if it's a few emails, via `validate_emails.py` script's self-hosted local email syntax, DNS and SMTP check

  ```
    validate_emails.py -f user@domain1.com -e user@yahoo.com -tm all
  [
      {
          "email": "user@yahoo.com",
          "status": "ok",
          "status_code": 250,
          "free_email": "yes",
          "disposable_email": "no"
      }
  ]
  ```

- MyEmailVerifier API is limited to 30 requests per minute for per email address verification checks. For the sample 15 email addresses tested below, took ~5.5 seconds to complete per email address verification checks
- MyEmailVerifier API logging doesn't seem to work. Waited a few days and none of my API tests were logged in their API logging on their dashboard web site.
- CaptainVerify API is limited to a maximum of 2 simultaneous connections and 50 checks per minute for per email address verification checks. For the sample 15 email addresses tested below, took ~4.6 seconds to complete per email address verification checks
- Proofy.io has the most restrictive API limits but I can't seem to find any documentation of the actual limits, so I have to code it so it isn't as fast as other providers for per email verification checks. It will be the slowest of the 5 providers for per email verification checks. For the sample 15 email addresses tested below, took ~9.5 seconds to complete per email address verification checks
- Proofy.io only has [single email check](https://proofy.io/using-api) and [batch email checks](https://proofy.io/using-api) but no bulk file API support.
- ZeroBounce API was added on May 11, 2024. For sample 15 email addresses, it took 4.794 seconds via per email check API. They have 100 free email credits per month, making it possible to keep my script's support and development testing costs down to a minimum. API documentation is very well documented. 
- ZeroBounce, only annoying issues right now are on their web site end and not their API specifically:
  1. initial login to web site dashboard are very slow as is reloading the dashboard i.e. browser F5 refresh. Sometimes just stuck with their purple reloading page progress icon that never actually loads the web page/dashboard.
  2. the web site login session durations are very short, so annoyingly you get logged out very quickly making it more secure. Make sure you use a password manager to make re-logins less annoying. Though if you're using a script and their API, you don't have to login as frequently.
- ZeroBounce offers per email, batch email and bulk file API endpoints. However, on trial freemium plan, I seem to be only able to get per email API to work. The batch email API seems to complain of invalid API key or no credits API response message, despite the single per email API working with the same API key and a positive credit balance.
- ZeroBounce doesn't charge for `unknown` status emails
- ZeroBounce API rate limit speeds are outlined in there documentation [here](https://www.zerobounce.net/docs/api-dashboard/#API_Rate_Limits) - 50,000 requests in 10 seconds (validations) before temporarily blocking for 1 minute. A maximum of 250 requests in 1 minute for the` bulkapi.zerobounce.net/` before temporarily blocking for 1 hour. And allow a maximum of 20 requests in 1 minute for the `bulkapi.zerobounce.net/v2/validatebatch` before temporarily blocking for 10 minutes. Rate limits seem more complicated so will need to test my script to ensure it operates under their rate limits.
- Reoon as added on May 12, 2024 and says they take around 20 minutes to verify a set of 50,000 mixed-quality email addresses. The 15 email address sameple test took 2.176 seconds to complete.
- Reoon unfortunately incorrectly classified `op999@gmail.com` as a `valid` email when it isn't and marked by all other APIs as `invalid`/`undeliverable`/`email_disabled`. This seems to be due to Reoon having 2 modes for their single email verification API for a `quick` and `power` modes. My initial tests are with `quick` mode. But I will need to do testing with `power` mode in future. Even their web site dashboard based single email verification check returns correct `invalid` status for this email suggesting they used `power` mode there too. I honestly do not know why anyone would use `quick` mode given how common Gmail email addresses are.
  - From their documentation:
    * The disadvantages of `quick` mode verification: Deep verification and detailed information are less available compared to the POWER mode. So individual inbox status will not be checked in this mode. The quick verification mode includes:
      * Email syntax validation.
      * Disposable/temporary email check.
      * MX validation and records.
      * Domain email acceptance validation.
      * Invalid email detection.
      * Expired/invalid domain detection.
      * Role account check.
- Reoon doesn't charge for `unknown` status emails
- Reoon do not store any uploaded data for more than 15 days
- Reon has detailed API credit usage and balance logs just like MillionVerifier
- Bouncify was added May 12, 2024 and seems to be the slowest to date for API response for single email and 15 sample email address API tests took 184+ seconds even though they have a 120 concurrent request API limit and seem to have trouble validating the `@yahoo.com` and `@hotmail.com` accounts in my 15 email address sample list [here](#bouncify-api).
- Bouncessless was added May 14, 2024. Probably the 2nd or 3rd slowest per email address verification APIs and seems highly inaccurate on 15 email address sample list not a single known valid email address was deemed as valid by the API. Instead the valid email addresses were all deemed `unknown`. After 1/2 day later I retested and Bounceless now fluctuates between an `unknown` and `valid` status for known Gmail address. So doesn't seem as reliable for detecting Gmail email addresses compared to other email verification providers tested and compared in the [Email Verification Results Table](#email-verification-results-table-compare). Bounceless API also doesn't recognise Gmail/Workspace emails using `+` alias i.e. `user+to@domain1.com` and deems them as invalid syntax! I double checked this on their web site dashboard and `user+to@domain1.com` email address was still marked as invalid syntax.
- The number of API returned status value classifications returned by the various providers differs. Some have a more detailed classifications for emails than others.
  - EmailListVerify has 18 classifications:
    - ok
    - error
    - invalid_mx
    - smtp_error
    - smtp_protocol
    - unknown_email
    - attempt_rejected
    - relay_error
    - antispam_system
    - email_disabled
    - domain_error
    - ok_for_all
    - dead_server
    - syntax_error
    - unknown
    - accept_all
    - disposable
    - spamtrap
  - MillionVerifier has 5 classifications:
    - ok
    - catch_all
    - unknown
    - disposable
    - invalid
  - MyEmailVerifier has 4 classifications:
    - valid
    - invalid
    - catch-all
    - unknown
  - CaptainVerify has 4 classifications:
    - valid
    - invalid
    - risky
    - unknown
  - Proofy.io has 4 classifications:
    - deliverable
    - risky
    - undeliverable
    - unknown
  - ZeroBounce has 7 classifications and also 23 `sub_status` classifications:
    - classifications:
      - valid
      - invalid
      - catch-all
      - unknown
      - spamtrap
      - abuse
      - do_not_mail
    - `sub_status` classifications:
      - alternate
      - antispam_system
      - greylisted
      - mail_server_temporary_error
      - forcible_disconnect
      - mail_server_did_not_respond
      - timeout_exceeded
      - failed_smtp_connection
      - mailbox_quota_exceeded
      - exception_occurred
      - possible_trap
      - role_based
      - global_suppression
      - mailbox_not_found
      - no_dns_entries
      - failed_syntax_check
      - possible_typo
      - unroutable_ip_address
      - leading_period_removed
      - does_not_accept_mail
      - alias_address
      - role_based_catch_all
      - disposable, toxic
  - Reoon has 4 classifications
    - valid
    - invalid
    - disposable
    - spamtrap
  - Bouncify has 4 classifications
    - deliverable
    - undeliverable
    - unknown
    - accept-all
  - Bounceless has [10 classifications](https://help.bounceless.io/en/article/3-terminology-and-result-codes)
    - blacklist
    - catch_all
    - disposable
    - invalid
    - no_mx_record
    - role
    - timeout
    - unknown
    - valid
    - spamtrap


## Email Verification Provider Comparison Costs

Below are their respectivate pay as you go credit pricing for email verifications. The usual recommendations are to verify your lists every 3-6 months which is 2-4x times per year. Have a 25K email list = 2-4 x 25K = 50-100K email verifications per year.

- Updates: 
  - May 11, 2024 add [Zerobounce](https://centminmod.com/zerobounce) API support
  - May 12, 2024 add [Reoon](https://centminmod.com/reoon) API support
  - May 12, 2024 add [Bouncify](https://centminmod.com/bouncify) API support
  - May 14, 2024 add [Bounceless](https://centminmod.com/bounceless) API support - seems there's difference in pricing for 500K on their web site at US$649 but logged into my dashboard pricing is US$799.

| Provider | 1k | 2k | 5k | 10k | 25k | 30k | 50k | 70k | 100k |
|----------------------------------|-----------|-----------|-----------|-----------|-----------|-----------|-----------|-----------|-----------|
| [EmailListVerify](https://centminmod.com/emaillistverify) ([demo](#emaillistverify-1), [results](#email-verification-results-table-compare)) | $4 (0.0008) | - | $15 (0.003)| $24 (0.0024)| $49 (0.00196)| - | $89 (0.00178)| - | $169 (0.00169)|
| [MillionVerifier](https://centminmod.com/millionverifier) ([demo](#millionverifier), [results](#email-verification-results-table-compare)) | - | - | - | $37 (0.0037)| $49 (0.00196)| - | $77 (0.00154)| - | $129 (0.00129)|
| [MyEmailVerifier](https://centminmod.com/myemailverifier) ([demo](#myemailverifier-api), [results](#email-verification-results-table-compare)) | - | $14 (0.007)| $28 (0.0056)| $39 (0.0039)| $79 (0.00316)| - | $149 (0.00298)| - | $239 (0.00239)|
| [CaptainVerify](https://centminmod.com/captainverify) ([demo](#captainverify-api), [results](#email-verification-results-table-compare)) | $7 (0.007) | - | $30 (0.006) | $60 (0.006) | $75 (0.003) | - | $150 (0.003) | - | $200 (0.002) |
| [Proofy.io](https://centminmod.com/proofy) ([demo](#proofy-api), [results](#email-verification-results-table-compare)) | - | - | $16 (0.0032)| $29 (0.0029)| - | $63 (0.0021)| $99 (0.00198)| $124 (0.00177)| $149 (0.00149)|
| [Zerobounce](https://centminmod.com/zerobounce) ([demo](#zerobounce-api), [results](#email-verification-results-table-compare)) | - | $20 (0.01) | $45 (0.009) | $80 (0.008) | $190 (0.0076) | - | $375 (0.0075) | - | $425 (0.00425) |
| [Reoon](https://centminmod.com/reoon) ([demo](#reoon-api), [results](#email-verification-results-table-compare)) | - | - | - | $11.91 (0.00119) | $29.66 (0.00119) | - | $58.95 (0.00118) | $87.86 (0.00126) | $116.40 (0.00116) |
| [Bouncify](https://centminmod.com/bouncify) ([demo](#bouncify-api), [results](#email-verification-results-table-compare)) | - | - | - | $19 (0.0019) | - | $39 (0.0013) | - | - | $99 (0.001) |
| [Bounceless](https://centminmod.com/bounceless) ([demo](#bounceless-api), [results](#email-verification-results-table-compare)) | - | - | $29 (0.0058) | - | $99 (0.00396) | - | - | - | $299 (0.00299) |

| Provider | 200k | 250k | 300k | 500k | 1m | 2.5m | 5m | 10m |
|----------------------------------|-----------|-----------|-----------|-----------|-----------|-----------|-----------|-----------|
| [EmailListVerify](https://centminmod.com/emaillistverify) ([demo](#emaillistverify-1), [results](#email-verification-results-table-compare)) | - | $349 (0.001396)| - | $449 (0.000898)| $599 (0.000599)| $1190 (0.000476)| $1990 (0.000398)| $3290 (0.000329)|
| [MillionVerifier](https://centminmod.com/millionverifier) ([demo](#millionverifier), [results](#email-verification-results-table-compare)) | - | - | - | $259 (0.000518)| $389 (0.000389)| - | $1439 (0.000288)| $2529 (0.000253)|
| [MyEmailVerifier](https://centminmod.com/myemailverifier) ([demo](#myemailverifier-api), [results](#email-verification-results-table-compare)) | - | $349 (0.001396)| - | $549 (0.001098)| $749 (0.000749)| $1249 (0.0005) | $1849 (0.00037)| - |
| [CaptainVerify](https://centminmod.com/captainverify) ([demo](#captainverify-api), [results](#email-verification-results-table-compare)) | - | $250 (0.001) | - | $500 (0.001) | $650 (0.00065)| - | $2000 (0.0004) | - |
| [Proofy.io](https://centminmod.com/proofy) ([demo](#proofy-api), [results](#email-verification-results-table-compare)) | $229 (0.001145)| - | $289 (0.000963)| $429 (0.000858)| $699 (0.000699)| $1399 (0.00056)| - | - |
| [Zerobounce](https://centminmod.com/zerobounce) ([demo](#zerobounce-api), [results](#email-verification-results-table-compare)) | - | $940 (0.00376) | - | $1800 (0.0036) | $2750 (0.00275) | - | - | - |
| [Reoon](https://centminmod.com/reoon) ([demo](#reoon-api), [results](#email-verification-results-table-compare)) | $226.80 (0.00113) | $279.75 (0.00112) | $331.20 (0.00110) | $522.00 (0.00104) | $960.00 (0.00096) | - | - | - |
| [Bouncify](https://centminmod.com/bouncify) ([demo](#bouncify-api), [results](#email-verification-results-table-compare)) | $149 (0.00075) | - | - | $279 (0.00056) | $479 (0.00048) | - | - | - |
| [Bounceless](https://centminmod.com/bounceless) ([demo](#bounceless-api), [results](#email-verification-results-table-compare)) | - | - | - | $649 (0.001298) | $899 (0.000899) | - | - | - |

## Email Verification Provider API Speed & Rate Limits

From fastest to slowest ranked from my API tests overall and from gathered API documentation from each respective email verification provider's web site. Speed wise on command line, [EmailListVerify](https://centminmod.com/emaillistverify) and [MillionVerifier](https://centminmod.com/millionverifier) are neck and neck on per email verification API checks. However, for bulk file API email verification checks, [MillionVerifier](https://centminmod.com/millionverifier) wins by a lot. Also added tests as a [PHP Wrapper](#php-wrapper) where each API providers' times performed differently compared to command line run tests.

MillionVerifier has more detailed email verification speed information for the bulk file email verification [here](https://help.millionverifier.com/bulk-email-verification/email-verification-speed) which I assume is for the web site dashboard and not for their API.

Updated: May 11, 2024 add [Zerobounce](https://centminmod.com/zerobounce) API support. ZeroBounce API rate limit speeds are outlined in there documentation [here](https://www.zerobounce.net/docs/api-dashboard/#API_Rate_Limits) and will update the below table after I have done some tests.

Updated: May 12, 2024 
  - add [Reoon](https://centminmod.com/reoon) API support. Will update below table after I have done some tests.
  - add [Bouncify](https://centminmod.com/bouncify) API support. Will update below table after I have done some tests.

Updated: May 14, 2024 
  - add [Bounceless](https://centminmod.com/bounceless) API support. Will update below table after I have done some tests.

Table also takes into account API rate limits besides my single and 15 email address sample tests. For example, if CaptainVerify takes 20+ seconds to verify a single email address and MyEmailVerifier takes 2-3 seconds, then the higher rate limit per min of CaptainVerify wouldn't matter as CaptainVerify would only be able to handle 3 emails/min versus MyEmailVerifier 20-30 emails/min.

| Provider Rank For API Speed      | emails/sec | emails/min |
|----------|--------------|-------------|
| 1. [MillionVerifier](https://centminmod.com/millionverifier)  | 400/s       | no doc mention     |
| 2. [EmailListVerify](https://centminmod.com/emaillistverify)  | no doc mention       | no doc mention      |
| 3. [Reoon](https://centminmod.com/reoon)  | no doc mention       | no doc mention      |
| 4. [Zerobounce](https://centminmod.com/zerobounce)  | 50,000 per 10s but 1 min block    | no doc mention      |
| 5. [MyEmailVerifier](https://centminmod.com/myemailverifier)  | no doc mention       | 30/min      |
| 6. [CaptainVerify](https://centminmod.com/captainverify)  | no doc mention       | 50/min      |
| 7. [Proofy.io](https://centminmod.com/proofy)  | no doc mention       | no doc mention      |
| 8. [Bounceless](https://centminmod.com/bounceless)  | no doc mention       | no doc mention      |
| 9. [Bouncify](https://centminmod.com/bouncify)  | no doc mention       | 120/min      |

## Email Verification Results Table Compare

Table comparing the JSON field values for each email address across the different Email cleaning service APIs and also compared to local script non-API queries results.

Tested on the same sample `emaillist.txt` of email addresses. These are their respective returned values for `status` JSON field which retrieved from the respective API services. While `status_code` (not used with external APIs), `free_email` and `disposable_email` JSON fields are from local script code/databases where applicable. The `sub_status` is a JSON field only for [Zerobounce](https://centminmod.com/zerobounce).

Pay attention to specific email addresses compared for the accuracy of the email verification providers's API results:

- `user@mailsac.com` this is a known disposable email address
- `xyz@centmil1.com` this is a domain that doesn't exist so would not have valid DNS or MX DNS records
- `user+to@domain1.com` this is a Google Workspace email address using `+` user aliasing and is a valid working email address
- `user@tempr.email` another known disposable email address
- `info@domain2.com` known valid Google Workspae email address that is working
- `user@gmail.com` known valid Gmail address
- `op999@gmail.com` known invalid user does not exist Gmail address AFAIKA
- `user@yahoo.com` known valid Yahoo email address that is working

| Email | API | status | sub_status | status_code | free_email | disposable_email |
|----------------------|-------------------|------------|-----------------|-------------|------------|------------------|
| user@mailsac.com | [EmailListVerify](https://centminmod.com/emaillistverify) | unknown | null | null | yes | yes |
| user@mailsac.com | [MillionVerifier](https://centminmod.com/millionverifier) | disposable | null | null | false | yes |
| user@mailsac.com | [CaptainVerify](https://centminmod.com/captainverify) | risky | null | null | no | yes |
| user@mailsac.com | [Proofy.io](https://centminmod.com/proofy) | undeliverable | null | null | no | yes |
| user@mailsac.com | [MyEmailVerifier](https://centminmod.com/myemailverifier) | invalid | null | null | yes | yes |
| user@mailsac.com | [Zerobounce](https://centminmod.com/zerobounce) | do_not_mail | disposable | null | yes | yes |
| user@mailsac.com | [Reoon](https://centminmod.com/reoon) | disposable | null | null | yes | yes |
| user@mailsac.com | [Bouncify](https://centminmod.com/bouncify) | undeliverable | null | null | yes | yes |
| user@mailsac.com | [Bounceless](https://centminmod.com/bounceless) | unknown | unknown | null | yes | yes |
| xyz@centmil1.com | [EmailListVerify](https://centminmod.com/emaillistverify) | unknown | null | null | no | no |
| xyz@centmil1.com | [MillionVerifier](https://centminmod.com/millionverifier) | invalid | null | null | false | no |
| xyz@centmil1.com | [CaptainVerify](https://centminmod.com/captainverify) | invalid | null | null | no | no |
| xyz@centmil1.com | [Proofy.io](https://centminmod.com/proofy) | undeliverable | null | null | no | no |
| xyz@centmil1.com | [MyEmailVerifier](https://centminmod.com/myemailverifier) | invalid | null | null | no | no |
| xyz@centmil1.com | [Zerobounce](https://centminmod.com/zerobounce) | invalid | no_dns_entries | null | no | no |
| xyz@centmil1.com | [Reoon](https://centminmod.com/reoon) | invalid | null | null | no | no |
| xyz@centmil1.com | [Bouncify](https://centminmod.com/bouncify) | undeliverable | null | null | no | no |
| xyz@centmil1.com | [Bounceless](https://centminmod.com/bounceless) | no_mx_record | no_mx_record | null | no | no |
| user+to@domain1.com | [EmailListVerify](https://centminmod.com/emaillistverify) | valid | null | null | no | no |
| user+to@domain1.com | [MillionVerifier](https://centminmod.com/millionverifier) | ok | null | null | false | no |
| user+to@domain1.com | [CaptainVerify](https://centminmod.com/captainverify) | valid | null | null | no | no |
| user+to@domain1.com | [Proofy.io](https://centminmod.com/proofy) | deliverable | null | null | no | no |
| user+to@domain1.com | [MyEmailVerifier](https://centminmod.com/myemailverifier) | valid | null | null | no | no |
| user+to@domain1.com | [Zerobounce](https://centminmod.com/zerobounce) | valid | alias_address | null | no | no |
| user+to@domain1.com | [Reoon](https://centminmod.com/reoon) | valid | null | null | no | no |
| user+to@domain1.com | [Bouncify](https://centminmod.com/bouncify) | deliverable | null | null | no | no |
| user+to@domain1.com | [Bounceless](https://centminmod.com/bounceless) | Invalid Syntax | Syntax Error | null | no | no |
| xyz@domain1.com | [EmailListVerify](https://centminmod.com/emaillistverify) | email_disabled | null | null | no | no |
| xyz@domain1.com | [MillionVerifier](https://centminmod.com/millionverifier) | invalid | null | null | false | no |
| xyz@domain1.com | [CaptainVerify](https://centminmod.com/captainverify) | invalid | null | null | no | no |
| xyz@domain1.com | [Proofy.io](https://centminmod.com/proofy) | undeliverable | null | null | no | no |
| xyz@domain1.com | [MyEmailVerifier](https://centminmod.com/myemailverifier) | invalid | null | null | no | no |
| xyz@domain1.com | [Zerobounce](https://centminmod.com/zerobounce) | invalid | mailbox_not_found | null | no | no |
| xyz@domain1.com | [Reoon](https://centminmod.com/reoon) | valid | null | null | no | no |
| xyz@domain1.com | [Bouncify](https://centminmod.com/bouncify) | undeliverable | null | null | no | no |
| xyz@domain1.com | [Bounceless](https://centminmod.com/bounceless) | unknown | unknown | null | no | no |
| abc@domain1.com | [EmailListVerify](https://centminmod.com/emaillistverify) | email_disabled | null | null | no | no |
| abc@domain1.com | [MillionVerifier](https://centminmod.com/millionverifier) | invalid | null | null | false | no |
| abc@domain1.com | [CaptainVerify](https://centminmod.com/captainverify) | invalid | null | null | no | no |
| abc@domain1.com | [Proofy.io](https://centminmod.com/proofy) | undeliverable | null | null | no | no |
| abc@domain1.com | [MyEmailVerifier](https://centminmod.com/myemailverifier) | invalid | null | null | no | no |
| abc@domain1.com | [Zerobounce](https://centminmod.com/zerobounce) | invalid | mailbox_not_found | null | no | no |
| abc@domain1.com | [Reoon](https://centminmod.com/reoon) | valid | null | null | no | no |
| abc@domain1.com | [Bouncify](https://centminmod.com/bouncify) | undeliverable | null | null | no | no |
| abc@domain1.com | [Bounceless](https://centminmod.com/bounceless) | unknown | unknown | null | no | no |
| 123@domain1.com | [EmailListVerify](https://centminmod.com/emaillistverify) | email_disabled | null | null | no | no |
| 123@domain1.com | [MillionVerifier](https://centminmod.com/millionverifier) | invalid | null | null | false | no |
| 123@domain1.com | [CaptainVerify](https://centminmod.com/captainverify) | risky | null | null | no | no |
| 123@domain1.com | [Proofy.io](https://centminmod.com/proofy) | undeliverable | null | null | no | no |
| 123@domain1.com | [MyEmailVerifier](https://centminmod.com/myemailverifier) | invalid | null | null | no | no |
| 123@domain1.com | [Zerobounce](https://centminmod.com/zerobounce) | invalid | mailbox_not_found | null | no | no |
| 123@domain1.com | [Reoon](https://centminmod.com/reoon) | valid | null | null | no | no |
| 123@domain1.com | [Bouncify](https://centminmod.com/bouncify) | undeliverable | null | null | no | no |
| 123@domain1.com | [Bounceless](https://centminmod.com/bounceless) | unknown | unknown | null | no | no |
| pop@domain1.com | [EmailListVerify](https://centminmod.com/emaillistverify) | email_disabled | null | null | no | no |
| pop@domain1.com | [MillionVerifier](https://centminmod.com/millionverifier) | invalid | null | null | false | no |
| pop@domain1.com | [CaptainVerify](https://centminmod.com/captainverify) | invalid | null | null | no | no |
| pop@domain1.com | [Proofy.io](https://centminmod.com/proofy) | undeliverable | null | null | no | no |
| pop@domain1.com | [MyEmailVerifier](https://centminmod.com/myemailverifier) | invalid | null | null | no | no |
| pop@domain1.com | [Zerobounce](https://centminmod.com/zerobounce) | invalid | mailbox_not_found | null | no | no |
| pop@domain1.com | [Reoon](https://centminmod.com/reoon) | valid | null | null | no | no |
| pop@domain1.com | [Bouncify](https://centminmod.com/bouncify) | undeliverable | null | null | no | no |
| pop@domain1.com | [Bounceless](https://centminmod.com/bounceless) | unknown | unknown | null | no | no |
| pip@domain1.com | [EmailListVerify](https://centminmod.com/emaillistverify) | email_disabled | null | null | no | no |
| pip@domain1.com | [MillionVerifier](https://centminmod.com/millionverifier) | invalid | null | null | false | no |
| pip@domain1.com | [CaptainVerify](https://centminmod.com/captainverify) | invalid | null | null | no | no |
| pip@domain1.com | [Proofy.io](https://centminmod.com/proofy) | undeliverable | null | null | no | no |
| pip@domain1.com | [MyEmailVerifier](https://centminmod.com/myemailverifier) | invalid | null | null | no | no |
| pip@domain1.com | [Zerobounce](https://centminmod.com/zerobounce) | invalid | mailbox_not_found | null | no | no |
| pip@domain1.com | [Reoon](https://centminmod.com/reoon) | valid | null | null | no | no |
| pip@domain1.com | [Bouncify](https://centminmod.com/bouncify) | undeliverable | null | null | no | no |
| pip@domain1.com | [Bounceless](https://centminmod.com/bounceless) | unknown | unknown | null | no | no |
| user@tempr.email | [EmailListVerify](https://centminmod.com/emaillistverify) | unknown | null | null | no | yes |
| user@tempr.email | [MillionVerifier](https://centminmod.com/millionverifier) | disposable | null | null | false | yes |
| user@tempr.email | [CaptainVerify](https://centminmod.com/captainverify) | risky | null | null | no | yes |
| user@tempr.email | [Proofy.io](https://centminmod.com/proofy) | undeliverable | null | null | no | yes |
| user@tempr.email | [MyEmailVerifier](https://centminmod.com/myemailverifier) | invalid | null | null | no | yes |
| user@tempr.email | [Zerobounce](https://centminmod.com/zerobounce) | do_not_mail | disposable | null | no | yes |
| user@tempr.email | [Reoon](https://centminmod.com/reoon) | disposable | null | null | yes | yes |
| user@tempr.email | [Bouncify](https://centminmod.com/bouncify) | undeliverable | null | null | no | yes |
| user@tempr.email | [Bounceless](https://centminmod.com/bounceless) | invalid | invalid | null | no | yes |
| info@domain2.com | [EmailListVerify](https://centminmod.com/emaillistverify) | valid | null | null | no | no |
| info@domain2.com | [MillionVerifier](https://centminmod.com/millionverifier) | ok | null | null | false | no |
| info@domain2.com | [CaptainVerify](https://centminmod.com/captainverify) | risky | null | null | no | no |
| info@domain2.com | [Proofy.io](https://centminmod.com/proofy) | deliverable | null | null | no | no |
| info@domain2.com | [MyEmailVerifier](https://centminmod.com/myemailverifier) | valid | null | null | no | no |
| info@domain2.com | [Zerobounce](https://centminmod.com/zerobounce) | do_not_mail | role_based | null | no | no |
| info@domain2.com | [Reoon](https://centminmod.com/reoon) | valid | null | null | no | no |
| info@domain2.com | [Bouncify](https://centminmod.com/bouncify) | deliverable | null | null | no | no |
| info@domain2.com | [Bounceless](https://centminmod.com/bounceless) | unknown | unknown | null | no | no |
| user@gmail.com | [EmailListVerify](https://centminmod.com/emaillistverify) | valid | null | null | yes | no |
| user@gmail.com | [MillionVerifier](https://centminmod.com/millionverifier) | ok | null | null | true | no |
| user@gmail.com | [CaptainVerify](https://centminmod.com/captainverify) | valid | null | null | yes | no |
| user@gmail.com | [Proofy.io](https://centminmod.com/proofy) | deliverable | null | null | yes | no |
| user@gmail.com | [MyEmailVerifier](https://centminmod.com/myemailverifier) | valid | null | null | yes | no |
| user@gmail.com | [Zerobounce](https://centminmod.com/zerobounce) | valid |  | null | yes | no |
| user@gmail.com | [Reoon](https://centminmod.com/reoon) | valid | null | null | yes | no |
| user@gmail.com | [Bouncify](https://centminmod.com/bouncify) | deliverable | null | null | yes | no |
| user@gmail.com | [Bounceless](https://centminmod.com/bounceless) | unknown | unknown | null | yes | no |
| op999@gmail.com | [EmailListVerify](https://centminmod.com/emaillistverify) | email_disabled | null | null | yes | no |
| op999@gmail.com | [MillionVerifier](https://centminmod.com/millionverifier) | invalid | null | null | true | no |
| op999@gmail.com | [CaptainVerify](https://centminmod.com/captainverify) | invalid | null | null | yes | no |
| op999@gmail.com | [Proofy.io](https://centminmod.com/proofy) | undeliverable | null | null | no | no |
| op999@gmail.com | [MyEmailVerifier](https://centminmod.com/myemailverifier) | invalid | null | null | yes | no |
| op999@gmail.com | [Zerobounce](https://centminmod.com/zerobounce) | invalid | mailbox_not_found | null | yes | no |
| op999@gmail.com | [Reoon](https://centminmod.com/reoon) | valid (quick mode) or invalid (power mode) | null | null | yes | no |
| op999@gmail.com | [Bouncify](https://centminmod.com/bouncify) | undeliverable | null | null | yes | no |
| op999@gmail.com | [Bounceless](https://centminmod.com/bounceless) | unknown | unknown | null | yes | no |
| user@yahoo.com | [EmailListVerify](https://centminmod.com/emaillistverify) | valid | null | null | yes | no |
| user@yahoo.com | [MillionVerifier](https://centminmod.com/millionverifier) | ok (per email API) or unknown (bulk email API) | null | null | true | no |
| user@yahoo.com | [CaptainVerify](https://centminmod.com/captainverify) | unknown | null | null | yes | no |
| user@yahoo.com | [Proofy.io](https://centminmod.com/proofy) | unknown | null | null | no | no |
| user@yahoo.com | [MyEmailVerifier](https://centminmod.com/myemailverifier) | valid | null | null | yes | no |
| user@yahoo.com | [Zerobounce](https://centminmod.com/zerobounce) | valid |  | null | yes | no |
| user@yahoo.com | [Reoon](https://centminmod.com/reoon) | valid | null | null | yes | no |
| user@yahoo.com | [Bouncify](https://centminmod.com/bouncify) | accept-all | null | null | yes | no |
| user@yahoo.com | [Bounceless](https://centminmod.com/bounceless) | unknown | unknown | null | yes | no |
| user1@outlook.com | [EmailListVerify](https://centminmod.com/emaillistverify) | valid | null | null | yes | no |
| user1@outlook.com | [MillionVerifier](https://centminmod.com/millionverifier) | ok | null | null | true | no |
| user1@outlook.com | [CaptainVerify](https://centminmod.com/captainverify) | valid | null | null | yes | no |
| user1@outlook.com | [Proofy.io](https://centminmod.com/proofy) | deliverable | null | null | yes | no |
| user1@outlook.com | [MyEmailVerifier](https://centminmod.com/myemailverifier) | valid | null | null | yes | no |
| user1@outlook.com | [Zerobounce](https://centminmod.com/zerobounce) | valid |  | null | yes | no |
| user1@outlook.com | [Reoon](https://centminmod.com/reoon) | valid | null | null | yes | no |
| user1@outlook.com | [Bouncify](https://centminmod.com/bouncify) | deliverable | null | null | yes | no | 
| user1@outlook.com | [Bounceless](https://centminmod.com/bounceless) | unknown | unknown | null | yes | no |
| user2@hotmail.com | [EmailListVerify](https://centminmod.com/emaillistverify) | valid | null | null | yes | no |
| user2@hotmail.com | [MillionVerifier](https://centminmod.com/millionverifier) | ok | null | null | true | no |
| user2@hotmail.com | [CaptainVerify](https://centminmod.com/captainverify) | valid | null | null | yes | no |  
| user2@hotmail.com | [Proofy.io](https://centminmod.com/proofy) | deliverable | null | null | yes | no |
| user2@hotmail.com | [MyEmailVerifier](https://centminmod.com/myemailverifier) | valid | null | null | yes | no |
| user2@hotmail.com | [Zerobounce](https://centminmod.com/zerobounce) | valid |  | null | yes | no |
| user2@hotmail.com | [Reoon](https://centminmod.com/reoon) | valid | null | null | yes | no |
| user2@hotmail.com | [Bouncify](https://centminmod.com/bouncify) | api_error | null | null | yes | no |
| user2@hotmail.com | [Bounceless](https://centminmod.com/bounceless) | unknown | unknown | null | yes | no |

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
- `spamtrap`  The email address is maintained by an ISP or a third party,which neither clicks nor opens emails
- `invalid_mx` An undocumentated status value that isn't in their documentation. As the name implies, invalid MX DNS records

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
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';\" xenforo"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';\" xenforo"
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
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';\" xenforo"
    },
    {
        "email": "abc@domain1.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';\" xenforo"
    },
    {
        "email": "123@domain1.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';\" xenforo"
    },
    {
        "email": "pop@domain1.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';\" xenforo"
    },
    {
        "email": "pip@domain1.com",
        "status": "email_disabled",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';\" xenforo"
    },
    {
        "email": "user@tempr.email",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';\" xenforo"
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
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';\" xenforo"
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
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';" xenforo
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
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';\" xenforo"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid",
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
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';\" xenforo"
    },
    {
        "email": "abc@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';\" xenforo"
    },
    {
        "email": "123@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';\" xenforo"
    },
    {
        "email": "pop@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';\" xenforo"
    },
    {
        "email": "pip@domain1.com",
        "status": "unknown_email",
        "status_code": 550,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';\" xenforo"
    },
    {
        "email": "user@tempr.email",
        "status": "ok",
        "status_code": 250,
        "free_email": "no",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';\" xenforo"
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
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';\" xenforo"
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

Also updated code to retrive API results for `free_email_api` and `role_api` while `free_email` and `disposable_email` are local script database lookup based

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api millionverifier -apikey_mv $mvkey
[
    {
        "email": "user@mailsac.com",
        "status": "disposable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "yes",
        "free_email_api": false,
        "role_api": true
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false
    },
    {
        "email": "user+to@domain1.com",
        "status": "ok",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false
    },
    {
        "email": "xyz@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false
    },
    {
        "email": "abc@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": true
    },
    {
        "email": "123@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false
    },
    {
        "email": "pop@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false
    },
    {
        "email": "pip@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false
    },
    {
        "email": "user@tempr.email",
        "status": "disposable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "free_email_api": false,
        "role_api": true
    },
    {
        "email": "info@domain2.com",
        "status": "ok",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": true
    },
    {
        "email": "user@gmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
    },
    {
        "email": "op999@gmail.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
    },
    {
        "email": "user@yahoo.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
    },
    {
        "email": "user1@outlook.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
    },
    {
        "email": "user2@hotmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
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
        "free_email": "yes",
        "disposable_email": "yes",
        "free_email_api": false,
        "role_api": true,
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';\" xenforo"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false,
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';\" xenforo"
    },
    {
        "email": "user+to@domain1.com",
        "status": "ok",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false
    },
    {
        "email": "xyz@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false,
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';\" xenforo"
    },
    {
        "email": "abc@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": true,
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';\" xenforo"
    },
    {
        "email": "123@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false,
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';\" xenforo"
    },
    {
        "email": "pop@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false,
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';\" xenforo"
    },
    {
        "email": "pip@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false,
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';\" xenforo"
    },
    {
        "email": "user@tempr.email",
        "status": "disposable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "free_email_api": false,
        "role_api": true,
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';\" xenforo"
    },
    {
        "email": "info@domain2.com",
        "status": "ok",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": true
    },
    {
        "email": "user@gmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
    },
    {
        "email": "op999@gmail.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false,
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';\" xenforo"
    },
    {
        "email": "user@yahoo.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
    },
    {
        "email": "user1@outlook.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
    },
    {
        "email": "user2@hotmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
    }
]
```

`jq` filterd for Xenforo MySQL queries only

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api millionverifier -apikey_mv $mvkey -xf -xfdb xenforo -xfprefix xf_ | jq -r '.[] | select(.xf_sql) | .xf_sql'

mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';" xenforo
```

### MillionVerifier Bulk File API

Added support for [MillionVerifier](https://centminmod.com/millionverifier) Bulk File API upload with added `-apibulk millionverifier` argument. Unfortunately for the below number of emails, the bulk API upload took a bit longer to process at 7 seconds versus 2.2 seconds for per email verification without `-apibulk millionverifier` due to remote processing.

```
cat email_verification_log_2024-05-06_05-36-30.log

2024-05-06 05:36:31,484 - INFO - Uploading file: emaillist.txt
2024-05-06 05:36:31,484 - INFO - Request URL: https://bulkapi.millionverifier.com/bulkapi/v2/upload?key=APIKEY&remove_duplicates=1
2024-05-06 05:36:31,484 - INFO - Request data: {'key': 'APIKEY'}
2024-05-06 05:36:31,484 - INFO - Request files: {'file_contents': <_io.BufferedReader name='emaillist.txt'>}
2024-05-06 05:36:31,765 - INFO - Response status code: 200
2024-05-06 05:36:31,765 - INFO - Response content: {
    "file_id": "26458323",
    "file_name": "emaillist.txt",
    "status": "unknown",
    "unique_emails": 0,
    "updated_at": "2024-05-06 05:36:31",
    "createdate": "2024-05-06 05:36:31",
    "percent": 0,
    "total_rows": 0,
    "verified": 0,
    "unverified": 0,
    "ok": 0,
    "catch_all": 0,
    "disposable": 0,
    "invalid": 0,
    "unknown": 0,
    "reverify": 0,
    "credit": 0,
    "estimated_time_sec": 0,
    "error": ""
}

2024-05-06 05:36:31,765 - INFO - Response JSON: {'file_id': '26458323', 'file_name': 'emaillist.txt', 'status': 'unknown', 'unique_emails': 0, 'updated_at': '2024-05-06 05:36:31', 'createdate': '2024-05-06 05:36:31', 'percent': 0, 'total_rows': 0, 'verified': 0, 'unverified': 0, 'ok': 0, 'catch_all': 0, 'disposable': 0, 'invalid': 0, 'unknown': 0, 'reverify': 0, 'credit': 0, 'estimated_time_sec': 0, 'error': ''}
2024-05-06 05:36:31,765 - INFO - File uploaded successfully. File ID: 26458323
2024-05-06 05:36:32,046 - INFO - File processing in progress. Progress: 0%
2024-05-06 05:36:37,328 - INFO - File processing completed. Retrieving results.
2024-05-06 05:36:37,607 - INFO - Results file downloaded: millionverifier_results_20240506053637.csv
2024-05-06 05:36:37,608 - INFO - Results retrieved successfully. Total lines: 15
```

with `-apibulk millionverifier` argument

Also updated code to retrive API results for `free_email_api` and `role_api` while `free_email` and `disposable_email` are local script database lookup based

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api millionverifier -apikey_mv $mvkey -apibulk millionverifier
[
    {
        "email": "user@mailsac.com",
        "status": "disposable",
        "free_email": "yes",
        "disposable_email": "yes",
        "free_email_api": "no",
        "role_api": "yes"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid",
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "role_api": "no"
    },
    {
        "email": "user+to@domain1.com",
        "status": "ok",
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "role_api": "no"
    },
    {
        "email": "user@tempr.email",
        "status": "disposable",
        "free_email": "no",
        "disposable_email": "yes",
        "free_email_api": "no",
        "role_api": "yes"
    },
    {
        "email": "info@domain2.com",
        "status": "ok",
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "role_api": "yes"
    },
    {
        "email": "xyz@domain1.com",
        "status": "invalid",
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "role_api": "no"
    },
    {
        "email": "abc@domain1.com",
        "status": "invalid",
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "role_api": "yes"
    },
    {
        "email": "123@domain1.com",
        "status": "invalid",
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "role_api": "no"
    },
    {
        "email": "pop@domain1.com",
        "status": "invalid",
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "role_api": "no"
    },
    {
        "email": "pip@domain1.com",
        "status": "invalid",
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "role_api": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "ok",
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "role_api": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "invalid",
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "role_api": "no"
    },
    {
        "email": "user@yahoo.com",
        "status": "unknown",
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "role_api": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "ok",
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "role_api": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "ok",
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "role_api": "no"
    }
]
```

without `-apibulk millionverifier` argument for per email checks

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api millionverifier -apikey_mv $mvkey
[
    {
        "email": "user@mailsac.com",
        "status": "disposable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "yes",
        "free_email_api": false,
        "role_api": true
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false
    },
    {
        "email": "user+to@domain1.com",
        "status": "ok",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false
    },
    {
        "email": "xyz@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false
    },
    {
        "email": "abc@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": true
    },
    {
        "email": "123@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false
    },
    {
        "email": "pop@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false
    },
    {
        "email": "pip@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": false
    },
    {
        "email": "user@tempr.email",
        "status": "disposable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "free_email_api": false,
        "role_api": true
    },
    {
        "email": "info@domain2.com",
        "status": "ok",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": false,
        "role_api": true
    },
    {
        "email": "user@gmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
    },
    {
        "email": "op999@gmail.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
    },
    {
        "email": "user@yahoo.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
    },
    {
        "email": "user1@outlook.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
    },
    {
        "email": "user2@hotmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
    }
]
```

## MillionVerifier Bulk API Differences

Noticed for below sample 15 email addresses tested, I always got 1 refunded credit so it applies to one email address which is a known valid email `user@yahoo.com` which is classed as `unknown` in bulk API but classed as `ok` in per email verification API. They refund credits for emails classified as 'risky' (`catch_all` or `unknown`) https://help.millionverifier.com/payments-credits/refund-for-risky-emails. Seems to be a bug in their bulk API then as the refunds only apply to bulk API and not per email verification checks due to differences in classifications in bulk API vs per email verification API. 

I reached out to MillionVerifier chat support which was initially handled via Milly their AI chat bot which later referred me to support. They emailed me back saying:

> We're glad you reached out to us about this issue, and we're here to help.
> The discrepancy you're seeing in the results is likely because we were unable to connect to the server during the verification process, leading to an "Unknown" result. However, for the single API, the connection went through smoothly, allowing us to verify the email without any problems. An "Unknown" result simply means that we couldn't determine the existence of the email at the time of verification.
> If you have any more questions, queries, or issues, we're more than happy to assist.

I tried a few attempts at bulk API for the same list of 15 emails, and `user@yahoo.com` is always marked as status = `unknown` and never anything different though? It would be hard to differentiate status classifications if it's due connection issues if they're lumped into other emails in unknown label. Maybe would be better to have a separate classification for connection issues so we can differentiate as such. For example, EmailListVerify has 18 different status classifications including for connection related issues.
  
single email API check for `user@yahoo.com` returns `ok`
```
python validate_emails.py -f user@domain1.com -e user@yahoo.com -api millionverifier -apikey_mv $mvkey -tm all
[
    {
        "email": "user@yahoo.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": true,
        "role_api": false
    }
]
```

bulk API upload check excerpt for `user@yahoo.com` returns `unknown`

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api millionverifier -apikey_mv $mvkey -apibulk millionverifier
[
 
    {
        "email": "user@yahoo.com",
        "status": "unknown",
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "role_api": "no"
    },

]
```
As such you can't 100% rely on the status output to do tasks like updating Xenforo user's `user_state` status to stop sending emails to them without further verification for such emails. For now, I've updated my `validate_emails.py` script for MillionVerifier bulk API and per email check API results, to not list [Xenforo SQL queries](#xenforo) for `unknown` status results and only list [Xenforo SQL queries](#xenforo) for `invalid` and `disposable` status emails. Same can be said for other providers, probably need to really double check your results if you're relying on the results for important tasks. You can filter MillionVerifier's `unknown` status emails and feed them into another commercial provider's API to double check i.e. EmailListVerify or use script's self-hosted local email check. Given cheaper MillionVerifier pricing, it might be more economical to do it this way?

MillionVerifier bulk API filter `-api millionverifier -apikey_mv $mvkey -apibulk millionverifier` filter using `jq` for `unknown` status emails piped into text file `results-millionverifier-bulk-api-unknown-only.txt`

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api millionverifier -apikey_mv $mvkey -apibulk millionverifier | jq '.[] | select(.status == "unknown")' 2>&1 > results-millionverifier-bulk-api-unknown-only.txt
```

The `results-millionverifier-bulk-api-unknown-only.txt` contents will show all MillionVerifier bulk API returned `unknown` status results.

```
cat results-millionverifier-bulk-api-unknown-only.txt                                            
{
  "email": "user@yahoo.com",
  "status": "unknown",
  "free_email": "yes",
  "disposable_email": "no",
  "free_email_api": "yes",
  "role_api": "no"
}
```

Using same `results-millionverifier-bulk-api-unknown-only.txt` file, and `jq` just filter out the email addresses into a new `results-millionverifier-bulk-api-unknown-only-emails.txt` file


```
cat results-millionverifier-bulk-api-unknown-only.txt | jq -r '.email' | tee results-millionverifier-bulk-api-unknown-only-emails.txt
user@yahoo.com
```

Then use EmailListVerify bulk API to verify the filtered MillionVerifier `unknown` status list filtered file `results-millionverifier-bulk-api-unknown-only-emails.txt` and double check the status which confirms it's actually a `valid` email.

```
python validate_emails.py -f user@domain1.com -l results-millionverifier-bulk-api-unknown-only-emails.txt -tm all -api emaillistverify -apikey $elvkey -apibulk emaillistverify

[
    {
        "email": "user@yahoo.com",
        "status": "valid",
        "status_code": "",
        "free_email": "yes",
        "disposable_email": "no"
    }
]
```

Or EmailListVerify per email verification API check

```
./validate_emails.py -f user@domain1.com -e user@yahoo.com -tm all -api emaillistverify -apikey $elvkey -tm all
[
    {
        "email": "user@yahoo.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    }
]
```

Or if it's a few emails, via `validate_emails.py` script's self-hosted local email syntax, DNS and SMTP check

```
  validate_emails.py -f user@domain1.com -e user@yahoo.com -tm all
[
    {
        "email": "user@yahoo.com",
        "status": "ok",
        "status_code": 250,
        "free_email": "yes",
        "disposable_email": "no"
    }
]
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
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';\" xenforo"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';\" xenforo"
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
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';\" xenforo"
    },
    {
        "email": "abc@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';\" xenforo"
    },
    {
        "email": "123@domain1.com",
        "status": "risky",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';\" xenforo"
    },
    {
        "email": "pop@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';\" xenforo"
    },
    {
        "email": "pip@domain1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';\" xenforo"
    },
    {
        "email": "user@tempr.email",
        "status": "risky",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';\" xenforo"
    },
    {
        "email": "info@domain2.com",
        "status": "risky",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'info@domain2.com';\" xenforo"
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
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';\" xenforo"
    },
    {
        "email": "user@yahoo.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@yahoo.com';\" xenforo"
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
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'info@domain2.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@yahoo.com';" xenforo
```

## Proofy API

Add [Proofy.io](https://centminmod.com/proofy) API support

[Proofy.io](https://centminmod.com/proofy) API enabled run `-api proofy -apikey_pf $pkey -apiuser_pf $puser`

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api proofy -apikey_pf $pkey -apiuser_pf $puser -xf -xfdb xenforo -xfprefix xf_
[
    {
        "email": "user@mailsac.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';\" xenforo"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';\" xenforo"
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
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';\" xenforo"
    },
    {
        "email": "abc@domain1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';\" xenforo"
    },
    {
        "email": "123@domain1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';\" xenforo"
    },
    {
        "email": "pop@domain1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';\" xenforo"
    },
    {
        "email": "pip@domain1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';\" xenforo"
    },
    {
        "email": "user@tempr.email",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';\" xenforo"
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
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';\" xenforo"
    },
    {
        "email": "user@yahoo.com",
        "status": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@yahoo.com';\" xenforo"
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
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'info@domain2.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@yahoo.com';" xenforo
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

mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';" xenforo
mysql -e "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';" xenforo
```

## Zerobounce API

Add [Zerobounce](https://centminmod.com/zerobounce) API support

[Zerobounce](https://centminmod.com/zerobounce) API enabled run `-api zerobounce -apikey_zb $zbkey -tm all` with specified email address `-e hnyfmw@canadlan-drugs.com`. The `status`, `sub_status` and `free_email_api` JSON fields are from API and `free_email` and `disposable_email` JSON fields are from local script database checks.

```
python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api zerobounce -apikey_zb $zbkey

[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "invalid",
        "sub_status": "no_dns_entries",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no"
    }
]
```

For email per verification API check for list of emails in `emaillist.txt` via `-l emaillist.txt`. The `status`, `sub_status` and `free_email_api` JSON fields are from API and `free_email` and `disposable_email` JSON fields are from local script database checks.

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api zerobounce -apikey_zb $zbkey
[
    {
        "email": "user@mailsac.com",
        "status": "do_not_mail",
        "sub_status": "disposable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "yes",
        "free_email_api": "yes"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid",
        "sub_status": "no_dns_entries",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no"
    },
    {
        "email": "user+to@domain1.com",
        "status": "valid",
        "sub_status": "alias_address",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "invalid",
        "sub_status": "mailbox_not_found",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no"
    },
    {
        "email": "abc@domain1.com",
        "status": "invalid",
        "sub_status": "mailbox_not_found",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no"
    },
    {
        "email": "123@domain1.com",
        "status": "invalid",
        "sub_status": "mailbox_not_found",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no"
    },
    {
        "email": "pop@domain1.com",
        "status": "invalid",
        "sub_status": "mailbox_not_found",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no"
    },
    {
        "email": "pip@domain1.com",
        "status": "invalid",
        "sub_status": "mailbox_not_found",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no"
    },
    {
        "email": "user@tempr.email",
        "status": "do_not_mail",
        "sub_status": "disposable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "free_email_api": "yes"
    },
    {
        "email": "info@domain2.com",
        "status": "do_not_mail",
        "sub_status": "role_based",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "valid",
        "sub_status": "",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes"
    },
    {
        "email": "op999@gmail.com",
        "status": "invalid",
        "sub_status": "mailbox_not_found",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes"
    },
    {
        "email": "user@yahoo.com",
        "status": "valid",
        "sub_status": "",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes"
    },
    {
        "email": "user1@outlook.com",
        "status": "valid",
        "sub_status": "",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes"
    },
    {
        "email": "user2@hotmail.com",
        "status": "valid",
        "sub_status": "",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes"
    }
]

real    0m4.794s
user    0m2.218s
sys     0m0.065s
```

Test ZeroBounce per email check API `-api zerobounce -apikey_zb $zbkey` with Cloudflare Cache `-apicache zerobounce -apicachettl 900`

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api zerobounce -apikey_zb $zbkey -tm all -apicache zerobounce -apicachettl 900

[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    }
]

real    0m0.777s
user    0m0.253s
sys     0m0.034s
```

Log inspection

```
cat $(ls -Art | tail -3 | grep 'email_verification')

2024-05-11 11:28:05,131 - INFO - Cache result: {'address': 'hnyfmw@canadlan-drugs.com', 'status': 'invalid', 'sub_status': 'no_dns_entries', 'free_email': False, 'did_you_mean': None, 'account': 'hnyfmw', 'domain': 'canadlan-drugs.com', 'domain_age_days': '2026', 'smtp_provider': '', 'mx_found': 'false', 'mx_record': '', 'firstname': None, 'lastname': None, 'gender': None, 'country': None, 'region': None, 'city': None, 'zipcode': None, 'processed_at': '2024-05-11 10:37:39.035'}
```

Cloudflare KV storage entries

| Key                                        | Value                                           |
|--------------------------------------------|--------------------------------------------------|
| zerobounce:hnyfmw@canadlan-drugs.com  | {"result":{"address":"hnyfmw@canadlan-drugs.com","status":"invalid","sub_status":"no_dns_entries","free_email":false,"did_you_mean":null,"account":"hnyfmw","domain":"canadlan-drugs.com","domain_age_days":"2026","smtp_provider":"","mx_found":"false","mx_record":"","firstname":null,"lastname":null,"gender":null,"country":null,"region":null,"city":null,"zipcode":null,"processed_at":"2024-05-11 11:39:24.133"},"timestamp":1715427564270,"ttl":900}  |

Test Cloudflare R2 storage via `-store r2` to save email verification results to Cloudflare R2 bucket directory at `emailapi-zerobounce-cached/output_20240511122039.json`

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api zerobounce -apikey_zb $zbkey -tm all -apicache zerobounce -apicachettl 900 -store r2

Output stored successfully in R2: emailapi-zerobounce-cached/output_20240511122039.json
[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    }
]

real    0m1.210s
user    0m0.355s
sys     0m0.031s
```

## Reoon API

Add [Reoon](https://centminmod.com/reoon) API support

[Reoon](https://centminmod.com/reoon) API enabled run `-api reoon -apikey_rn $reokey -tm all` with specified email address `-e hnyfmw@canadlan-drugs.com`. The `status`, `role_account`, `mx_accepts_mail`, `spamtrap`, `mx_records`, `overall_score`, `safe_to_send`, `can_connect_smtp`, `inbox_full`, `catch_all`, `deliverable`, `disabled` JSON field is from API and `free_email` and `disposable_email` JSON fields are from local script database checks.

Reoon has 2 modes for single email verification API which can be set via `-reoon_mode` to a value of either `quick` or `power`. The default mode without `-reoon_mode` being set is `quick`.

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api reoon -apikey_rn $reokey

[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "role_account": "no",
        "mx_accepts_mail": "no",
        "spamtrap": "no",
        "mx_records": null,
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    }
]

real    0m3.748s
user    0m0.358s
sys     0m0.028s
```

With `-reoon_mode power`. Currently, script hasn't been configured to grab the additional information provided by `power` mode.

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api reoon -apikey_rn $reokey -reoon_mode power

[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "role_account": "no",
        "mx_accepts_mail": "no",
        "spamtrap": "no",
        "mx_records": [],
        "verification_mode": "power",
        "overall_score": 0,
        "safe_to_send": "no",
        "can_connect_smtp": "no",
        "inbox_full": "no",
        "catch_all": "no",
        "deliverable": "no",
        "disabled": "no"
    }
]

real    0m3.196s
user    0m0.360s
sys     0m0.026s
```

For email per verification API check for list of emails in `emaillist.txt` via `-l emaillist.txt`. The `status` JSON field is from API and `free_email` and `disposable_email` JSON fields are from local script database checks.

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api reoon -apikey_rn $reokey

[
    {
        "email": "user@mailsac.com",
        "status": "disposable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "yes",
        "role_account": "yes",
        "mx_accepts_mail": "yes",
        "spamtrap": "no",
        "mx_records": [
            "in.mailsac.com",
            "alt.mailsac.com"
        ],
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    },
    {
        "email": "xyz@centmil1.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "role_account": "no",
        "mx_accepts_mail": "no",
        "spamtrap": "no",
        "mx_records": null,
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    },
    {
        "email": "user+to@domain1.com",
        "status": "valid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "role_account": "no",
        "mx_accepts_mail": "yes",
        "spamtrap": "no",
        "mx_records": [
            "aspmx.l.google.com",
            "alt1.aspmx.l.google.com",
            "alt2.aspmx.l.google.com",
            "aspmx2.googlemail.com",
            "aspmx4.googlemail.com",
            "aspmx3.googlemail.com",
            "aspmx5.googlemail.com"
        ],
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    },
    {
        "email": "xyz@domain1.com",
        "status": "valid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "role_account": "no",
        "mx_accepts_mail": "yes",
        "spamtrap": "no",
        "mx_records": [
            "aspmx.l.google.com",
            "alt1.aspmx.l.google.com",
            "alt2.aspmx.l.google.com",
            "aspmx2.googlemail.com",
            "aspmx4.googlemail.com",
            "aspmx3.googlemail.com",
            "aspmx5.googlemail.com"
        ],
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    },
    {
        "email": "abc@domain1.com",
        "status": "valid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "role_account": "yes",
        "mx_accepts_mail": "yes",
        "spamtrap": "no",
        "mx_records": [
            "aspmx.l.google.com",
            "alt1.aspmx.l.google.com",
            "alt2.aspmx.l.google.com",
            "aspmx2.googlemail.com",
            "aspmx4.googlemail.com",
            "aspmx3.googlemail.com",
            "aspmx5.googlemail.com"
        ],
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    },
    {
        "email": "123@domain1.com",
        "status": "valid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "role_account": "yes",
        "mx_accepts_mail": "yes",
        "spamtrap": "no",
        "mx_records": [
            "aspmx.l.google.com",
            "alt1.aspmx.l.google.com",
            "alt2.aspmx.l.google.com",
            "aspmx2.googlemail.com",
            "aspmx4.googlemail.com",
            "aspmx3.googlemail.com",
            "aspmx5.googlemail.com"
        ],
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    },
    {
        "email": "pop@domain1.com",
        "status": "valid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "role_account": "no",
        "mx_accepts_mail": "yes",
        "spamtrap": "no",
        "mx_records": [
            "aspmx.l.google.com",
            "alt1.aspmx.l.google.com",
            "alt2.aspmx.l.google.com",
            "aspmx2.googlemail.com",
            "aspmx4.googlemail.com",
            "aspmx3.googlemail.com",
            "aspmx5.googlemail.com"
        ],
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    },
    {
        "email": "pip@domain1.com",
        "status": "valid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "role_account": "no",
        "mx_accepts_mail": "yes",
        "spamtrap": "no",
        "mx_records": [
            "aspmx.l.google.com",
            "alt1.aspmx.l.google.com",
            "alt2.aspmx.l.google.com",
            "aspmx2.googlemail.com",
            "aspmx4.googlemail.com",
            "aspmx3.googlemail.com",
            "aspmx5.googlemail.com"
        ],
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    },
    {
        "email": "user@tempr.email",
        "status": "disposable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "yes",
        "role_account": "yes",
        "mx_accepts_mail": "yes",
        "spamtrap": "no",
        "mx_records": [
            "mx.discard.email"
        ],
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    },
    {
        "email": "info@domain2.com",
        "status": "valid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "role_account": "yes",
        "mx_accepts_mail": "yes",
        "spamtrap": "no",
        "mx_records": [
            "aspmx.l.google.com",
            "alt2.aspmx.l.google.com",
            "alt1.aspmx.l.google.com",
            "aspmx2.googlemail.com",
            "aspmx5.googlemail.com",
            "aspmx3.googlemail.com",
            "aspmx4.googlemail.com"
        ],
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    },
    {
        "email": "user@gmail.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "role_account": "no",
        "mx_accepts_mail": "yes",
        "spamtrap": "no",
        "mx_records": [
            "gmail-smtp-in.l.google.com",
            "alt1.gmail-smtp-in.l.google.com",
            "alt2.gmail-smtp-in.l.google.com",
            "alt3.gmail-smtp-in.l.google.com",
            "alt4.gmail-smtp-in.l.google.com"
        ],
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    },
    {
        "email": "op999@gmail.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "role_account": "no",
        "mx_accepts_mail": "yes",
        "spamtrap": "no",
        "mx_records": [
            "gmail-smtp-in.l.google.com",
            "alt1.gmail-smtp-in.l.google.com",
            "alt2.gmail-smtp-in.l.google.com",
            "alt3.gmail-smtp-in.l.google.com",
            "alt4.gmail-smtp-in.l.google.com"
        ],
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    },
    {
        "email": "user@yahoo.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "role_account": "no",
        "mx_accepts_mail": "yes",
        "spamtrap": "no",
        "mx_records": [
            "mta7.am0.yahoodns.net",
            "mta5.am0.yahoodns.net",
            "mta6.am0.yahoodns.net"
        ],
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    },
    {
        "email": "user1@outlook.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "role_account": "no",
        "mx_accepts_mail": "yes",
        "spamtrap": "no",
        "mx_records": [
            "outlook-com.olc.protection.outlook.com"
        ],
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    },
    {
        "email": "user2@hotmail.com",
        "status": "valid",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "role_account": "no",
        "mx_accepts_mail": "yes",
        "spamtrap": "no",
        "mx_records": [
            "hotmail-com.olc.protection.outlook.com"
        ],
        "verification_mode": "quick",
        "overall_score": null,
        "safe_to_send": null,
        "can_connect_smtp": null,
        "inbox_full": null,
        "catch_all": null,
        "deliverable": null,
        "disabled": null
    }
]

real    0m2.176s
user    0m2.350s
sys     0m0.050s
```

# Bouncify API

Add [Bouncify](https://centminmod.com/bouncify) API support

[Bouncify](https://centminmod.com/bouncify) API enabled run `-api bouncify -apikey_bf $bfkey -tm all` with specified email address `-e hnyfmw@canadlan-drugs.com`. The `status`, `free_email_api`, `disposable_email_api`, `role_api`, and `spamtrap_api` JSON field are from API and `free_email` and `disposable_email` JSON fields are from local script database checks.

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api bouncify -apikey_bf $bfkey
[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    }
]

real    0m7.900s
user    0m0.357s
sys     0m0.030s
```

For email per verification API check for list of emails in `emaillist.txt` via `-l emaillist.txt`. The `status`, `free_email_api`, `disposable_email_api`, `role_api`, and `spamtrap_api` JSON field are from API and `free_email` and `disposable_email` JSON fields are from local script database checks.

Seems to be the slowest API processing time email verification providers tested to date and had a API issues. The diagnostic log shows that Bouncify API marked incorrectly that the `user@yahoo.com` email address as an `accept-all` email address and validation for `user2@hotmail.com` email address timed out. Their API docs at https://bouncify.readme.io/reference/single-validation-api, suggest a 120 concurrent request API limit and that `Apart from undeliverable, for the results deliverable, accept-all and unknown do not reject the email address and proceed with your work flow. Both accept-all and unknown emails could not be validated, so they may be valid email address.`

```
2024-05-12 12:44:44,519 - ERROR - Unexpected API response for user2@hotmail.com: {'result': 'Validation timedout', 'success': False}
```

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api bouncify -apikey_bf $bfkey
[
    {
        "email": "user@mailsac.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "yes",
        "free_email_api": "yes",
        "disposable_email_api": "yes",
        "role_api": "yes",
        "spamtrap_api": "no"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    },
    {
        "email": "user+to@domain1.com",
        "status": "deliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    },
    {
        "email": "abc@domain1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    },
    {
        "email": "123@domain1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    },
    {
        "email": "pop@domain1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    },
    {
        "email": "pip@domain1.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    },
    {
        "email": "user@tempr.email",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "free_email_api": "no",
        "disposable_email_api": "yes",
        "role_api": "yes",
        "spamtrap_api": "no"
    },
    {
        "email": "info@domain2.com",
        "status": "deliverable",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "disposable_email_api": "no",
        "role_api": "yes",
        "spamtrap_api": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "deliverable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "undeliverable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    },
    {
        "email": "user@yahoo.com",
        "status": "accept-all",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "deliverable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "api_error",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "no",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    }
]

real    3m4.412s
user    0m2.366s
sys     0m0.049s
```

Re-trying the Hotmail `user2@hotmail.com` re-tried individually worked without timeouts

```
time python validate_emails.py -f user@domain1.com -e user2@hotmail.com -tm all -api bouncify -apikey_bf $bfkey
[
    {
        "email": "user2@hotmail.com",
        "status": "deliverable",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "no",
        "spamtrap_api": "no"
    }
]

real    0m3.516s
user    0m0.362s
sys     0m0.025s
```

## Bounceless API

Add [Bounceless](https://centminmod.com/bounceless) API support

[Bounceless](https://centminmod.com/bounceless) API enabled run `-api bounceless -apikey_bl $blkey -tm all` with specified email address `-e hnyfmw@canadlan-drugs.com`. The `status`, `reason`, `free_email_api`, `disposable_email_api`, `role_api` and `accept_all` JSON fields are from API and `free_email` and `disposable_email` JSON fields are from local script database checks.

This returned a correct status result of `no_mx_record` as expected, but the 15 email address sample test further below was highly inaccurate for known valid email addresses as you can see.

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api bounceless -apikey_bl $blkey

[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "no_mx_record",
        "reason": "no_mx_record",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "disposable_email_api": "no",
        "role_api": "no",
        "accept_all": "no"
    }
]

real    0m2.582s
user    0m0.395s
sys     0m0.022s
```

For email per verification API check for list of emails in `emaillist.txt` via `-l emaillist.txt`. The `status`, `reason`, `free_email_api`, `disposable_email_api`, `role_api` and `accept_all` JSON fields are from API and `free_email` and `disposable_email` JSON fields are from local script database checks.

Unfortunately, this has to be the worse email verification result I have received for my sample 15 email addresses compared to all other commercial email verification providers. All the known valid emails are marked as `unknown` - not 1 valid email address below was marked correctly as valid! I double checked on their web dashboard inputting single known valid email addresses and they return the same incorrect status as below API results gave.

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api bounceless -apikey_bl $blkey
[
    {
        "email": "user@mailsac.com",
        "status": "unknown",
        "reason": "unknown",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "yes",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "yes",
        "accept_all": "no"
    },
    {
        "email": "xyz@centmil1.com",
        "status": "no_mx_record",
        "reason": "no_mx_record",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "no",
        "disposable_email_api": "no",
        "role_api": "no",
        "accept_all": "no"
    },
    {
        "email": "user+to@domain1.com",
        "status": "Invalid Syntax",
        "reason": "Syntax Error",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "yes",
        "accept_all": "no"
    },
    {
        "email": "xyz@domain1.com",
        "status": "unknown",
        "reason": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "yes",
        "accept_all": "no"
    },
    {
        "email": "abc@domain1.com",
        "status": "unknown",
        "reason": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "yes",
        "accept_all": "no"
    },
    {
        "email": "123@domain1.com",
        "status": "unknown",
        "reason": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "yes",
        "accept_all": "no"
    },
    {
        "email": "pop@domain1.com",
        "status": "unknown",
        "reason": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "yes",
        "accept_all": "no"
    },
    {
        "email": "pip@domain1.com",
        "status": "unknown",
        "reason": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "yes",
        "accept_all": "no"
    },
    {
        "email": "user@tempr.email",
        "status": "invalid",
        "reason": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "yes",
        "free_email_api": "no",
        "disposable_email_api": "yes",
        "role_api": "no",
        "accept_all": "no"
    },
    {
        "email": "info@domain2.com",
        "status": "unknown",
        "reason": "unknown",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "yes",
        "accept_all": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "unknown",
        "reason": "unknown",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "yes",
        "accept_all": "no"
    },
    {
        "email": "op999@gmail.com",
        "status": "unknown",
        "reason": "unknown",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "yes",
        "accept_all": "no"
    },
    {
        "email": "user@yahoo.com",
        "status": "unknown",
        "reason": "unknown",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "yes",
        "accept_all": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "unknown",
        "reason": "unknown",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "yes",
        "accept_all": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "unknown",
        "reason": "unknown",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no",
        "free_email_api": "yes",
        "disposable_email_api": "no",
        "role_api": "yes",
        "accept_all": "no"
    }
]

real    0m22.085s
user    0m2.354s
sys     0m0.061s
```

To confirm and verify, I tested Bounceless's API directly and same result for known valid email address `user@gmail.com` which returns a `result` of `unknown`! Also API response time was very slow for single email verification result at 15.825s and for above 15 email address samples was 22.085s.

```
time curl -s "https://apps.bounceless.io/api/singlemaildetails?secret=$blkey&email=user@gmail.com" | jq -r

{
  "success": true,
  "accept_all": false,
  "result": "unknown",
  "reason": "unknown",
  "role": true,
  "free": true,
  "disposable": false,
  "user": "",
  "domain": "",
  "email": "user@gmail.com",
  "did_you_mean": null,
  "message": ""
}

real    0m15.825s
user    0m0.028s
sys     0m0.004s
```

After 1/2 day, I tried retesting Bounceless API against known valid Gmail address, and it seems it fluctuates between a result status of `unknown` and `valid` between runs. Maybe it's due to some security mechanisms on Gmail's server end but other commercial provider's APIs have always returned correctly for this known valid Gmail address. Note though the slower API result times >12-15 seconds remain.

```
time curl -s "https://apps.bounceless.io/api/singlemaildetails?secret=$blkey&email=user@gmail.com" | jq -r
{
  "success": true,
  "accept_all": false,
  "result": "valid",
  "reason": "valid",
  "role": false,
  "free": true,
  "disposable": false,
  "user": "user",
  "domain": "gmail.com",
  "email": "user@gmail.com",
  "did_you_mean": null,
  "message": ""
}

real    0m12.500s
user    0m0.029s
sys     0m0.004s
```

# API Merge

Added support for `-apimerge` argument which allows you to merge Merging [EmailListVerify](https://centminmod.com/emaillistverify) + [MillionVerifier](https://centminmod.com/millionverifier) API results together for more accurate email verification results. 

The table below shows how long it took to execute and process the verification checks using `validate_emails.py` and merged APIs. Looks like subsequent runs were faster due to probably primed caches at respective providers' backends.

| API Merge Command | Processing Time |
|-------------------|-----------------|
| Per Email Verification | 15.946 seconds |
| Bulk API File Upload | 47.536 seconds |
| Per Email Verification with Xenforo | 10.666 seconds |
| Bulk API File Upload with Xenforo | 41.260 seconds |

Merging [EmailListVerify](https://centminmod.com/emaillistverify) + [MillionVerifier](https://centminmod.com/millionverifier) API results for both into one JSON result output for per email verification checks

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api emaillistverify -apikey $elvkey -api millionverifier -apikey_mv $mvkey -apimerge
[
    {
        "email": "user@mailsac.com",
        "elv_status": "disposable",
        "elv_status_code": null,
        "elv_free_email": "yes",
        "elv_disposable_email": "yes",
        "mv_status": "disposable",
        "mv_status_code": null,
        "mv_free_email": "yes",
        "mv_disposable_email": "yes",
        "mv_free_email_api": false,
        "mv_role_api": true
    },
    {
        "email": "xyz@centmil1.com",
        "elv_status": "invalid",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": false
    },
    {
        "email": "user+to@domain1.com",
        "elv_status": "ok",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": false
    },
    {
        "email": "user@tempr.email",
        "elv_status": "disposable",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "yes",
        "mv_status": "disposable",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "yes",
        "mv_free_email_api": false,
        "mv_role_api": true
    },
    {
        "email": "info@domain2.com",
        "elv_status": "ok",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": true
    },
    {
        "email": "xyz@domain1.com",
        "elv_status": "invalid",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": false
    },
    {
        "email": "abc@domain1.com",
        "elv_status": "invalid",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": true
    },
    {
        "email": "123@domain1.com",
        "elv_status": "invalid",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": false
    },
    {
        "email": "pop@domain1.com",
        "elv_status": "invalid",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": false
    },
    {
        "email": "pip@domain1.com",
        "elv_status": "invalid",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": false
    },
    {
        "email": "user@gmail.com",
        "elv_status": "ok",
        "elv_status_code": null,
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_status_code": null,
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": true,
        "mv_role_api": false
    },
    {
        "email": "op999@gmail.com",
        "elv_status": "invalid",
        "elv_status_code": null,
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_status_code": null,
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": true,
        "mv_role_api": false
    },
    {
        "email": "user@yahoo.com",
        "elv_status": "ok",
        "elv_status_code": null,
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_status_code": null,
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": true,
        "mv_role_api": false
    },
    {
        "email": "user1@outlook.com",
        "elv_status": "ok",
        "elv_status_code": null,
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_status_code": null,
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": true,
        "mv_role_api": false
    },
    {
        "email": "user2@hotmail.com",
        "elv_status": "ok",
        "elv_status_code": null,
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_status_code": null,
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": true,
        "mv_role_api": false
    }
]

real    0m15.946s
user    0m1.017s
sys     0m0.037s
```

Merging [EmailListVerify](https://centminmod.com/emaillistverify) + [MillionVerifier](https://centminmod.com/millionverifier) API results for both into one JSON result output for bulk API file upload checks `-apibulk`

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api emaillistverify -apikey $elvkey -apibulk emaillistverify -api millionverifier -apikey_mv $mvkey -apibulk millionverifier -apimerge

[
    {
        "email": "user@mailsac.com",
        "elv_status": "disposable",
        "elv_status_code": "",
        "elv_free_email": "yes",
        "elv_disposable_email": "yes",
        "mv_status": "disposable",
        "mv_free_email": "yes",
        "mv_disposable_email": "yes",
        "mv_free_email_api": "no",
        "mv_role_api": "yes"
    },
    {
        "email": "xyz@centmil1.com",
        "elv_status": "dead_server",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "no"
    },
    {
        "email": "user+to@domain1.com",
        "elv_status": "valid",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "no"
    },
    {
        "email": "user@tempr.email",
        "elv_status": "disposable",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "yes",
        "mv_status": "disposable",
        "mv_free_email": "no",
        "mv_disposable_email": "yes",
        "mv_free_email_api": "no",
        "mv_role_api": "yes"
    },
    {
        "email": "info@domain2.com",
        "elv_status": "valid",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "yes"
    },
    {
        "email": "xyz@domain1.com",
        "elv_status": "email_disabled",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "no"
    },
    {
        "email": "abc@domain1.com",
        "elv_status": "email_disabled",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "yes"
    },
    {
        "email": "123@domain1.com",
        "elv_status": "email_disabled",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "no"
    },
    {
        "email": "pop@domain1.com",
        "elv_status": "email_disabled",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "no"
    },
    {
        "email": "pip@domain1.com",
        "elv_status": "email_disabled",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "no"
    },
    {
        "email": "user@gmail.com",
        "elv_status": "valid",
        "elv_status_code": "",
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": "yes",
        "mv_role_api": "no"
    },
    {
        "email": "op999@gmail.com",
        "elv_status": "email_disabled",
        "elv_status_code": "",
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": "yes",
        "mv_role_api": "no"
    },
    {
        "email": "user@yahoo.com",
        "elv_status": "valid",
        "elv_status_code": "",
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "unknown",
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": "yes",
        "mv_role_api": "no"
    },
    {
        "email": "user1@outlook.com",
        "elv_status": "valid",
        "elv_status_code": "",
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": "yes",
        "mv_role_api": "no"
    },
    {
        "email": "user2@hotmail.com",
        "elv_status": "valid",
        "elv_status_code": "",
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": "yes",
        "mv_role_api": "no"
    }
]

real    0m47.536s
user    0m0.612s
sys     0m0.021s
```

Merging [EmailListVerify](https://centminmod.com/emaillistverify) + [MillionVerifier](https://centminmod.com/millionverifier) API results for both into one JSON result output for per email verification checks + Xenforo flags

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api emaillistverify -apikey $elvkey -api millionverifier -apikey_mv $mvkey -apimerge -xf -xfdb xenforo -xfprefix xf_

[
    {
        "email": "user@mailsac.com",
        "elv_status": "disposable",
        "elv_status_code": null,
        "elv_free_email": "yes",
        "elv_disposable_email": "yes",
        "mv_status": "disposable",
        "mv_status_code": null,
        "mv_free_email": "yes",
        "mv_disposable_email": "yes",
        "mv_free_email_api": false,
        "mv_role_api": true,
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'user@mailsac.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'user@mailsac.com'\\G\" xenforo"
    },
    {
        "email": "xyz@centmil1.com",
        "elv_status": "invalid",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": false,
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'xyz@centmil1.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'xyz@centmil1.com'\\G\" xenforo"
    },
    {
        "email": "user+to@domain1.com",
        "elv_status": "ok",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": false
    },
    {
        "email": "user@tempr.email",
        "elv_status": "disposable",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "yes",
        "mv_status": "disposable",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "yes",
        "mv_free_email_api": false,
        "mv_role_api": true,
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'user@tempr.email'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'user@tempr.email'\\G\" xenforo"
    },
    {
        "email": "info@domain2.com",
        "elv_status": "ok",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": true
    },
    {
        "email": "xyz@domain1.com",
        "elv_status": "invalid",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": false,
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'xyz@domain1.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'xyz@domain1.com'\\G\" xenforo"
    },
    {
        "email": "abc@domain1.com",
        "elv_status": "invalid",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": true,
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'abc@domain1.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'abc@domain1.com'\\G\" xenforo"
    },
    {
        "email": "123@domain1.com",
        "elv_status": "invalid",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": false,
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = '123@domain1.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = '123@domain1.com'\\G\" xenforo"
    },
    {
        "email": "pop@domain1.com",
        "elv_status": "invalid",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": false,
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'pop@domain1.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'pop@domain1.com'\\G\" xenforo"
    },
    {
        "email": "pip@domain1.com",
        "elv_status": "invalid",
        "elv_status_code": null,
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_status_code": null,
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": false,
        "mv_role_api": false,
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'pip@domain1.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'pip@domain1.com'\\G\" xenforo"
    },
    {
        "email": "user@gmail.com",
        "elv_status": "ok",
        "elv_status_code": null,
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_status_code": null,
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": true,
        "mv_role_api": false
    },
    {
        "email": "op999@gmail.com",
        "elv_status": "invalid",
        "elv_status_code": null,
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_status_code": null,
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": true,
        "mv_role_api": false,
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'op999@gmail.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'op999@gmail.com'\\G\" xenforo"
    },
    {
        "email": "user@yahoo.com",
        "elv_status": "ok",
        "elv_status_code": null,
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_status_code": null,
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": true,
        "mv_role_api": false
    },
    {
        "email": "user1@outlook.com",
        "elv_status": "ok",
        "elv_status_code": null,
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_status_code": null,
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": true,
        "mv_role_api": false
    },
    {
        "email": "user2@hotmail.com",
        "elv_status": "ok",
        "elv_status_code": null,
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_status_code": null,
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": true,
        "mv_role_api": false
    }
]

real    0m10.666s
user    0m1.008s
sys     0m0.034s
```

Merging [EmailListVerify](https://centminmod.com/emaillistverify) + [MillionVerifier](https://centminmod.com/millionverifier) API results for both into one JSON result output for bulk API file upload checks `-apibulk` + Xenforo flags

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api emaillistverify -apikey $elvkey -apibulk emaillistverify -api millionverifier -apikey_mv $mvkey -apibulk millionverifier -apimerge -xf -xfdb xenforo -xfprefix xf_

[
    {
        "email": "user@mailsac.com",
        "elv_status": "disposable",
        "elv_status_code": "",
        "elv_free_email": "yes",
        "elv_disposable_email": "yes",
        "mv_status": "disposable",
        "mv_free_email": "yes",
        "mv_disposable_email": "yes",
        "mv_free_email_api": "no",
        "mv_role_api": "yes",
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'user@mailsac.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@mailsac.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'user@mailsac.com'\\G\" xenforo"
    },
    {
        "email": "xyz@centmil1.com",
        "elv_status": "dead_server",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "no",
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'xyz@centmil1.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@centmil1.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'xyz@centmil1.com'\\G\" xenforo"
    },
    {
        "email": "user+to@domain1.com",
        "elv_status": "valid",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "no"
    },
    {
        "email": "user@tempr.email",
        "elv_status": "disposable",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "yes",
        "mv_status": "disposable",
        "mv_free_email": "no",
        "mv_disposable_email": "yes",
        "mv_free_email_api": "no",
        "mv_role_api": "yes",
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'user@tempr.email'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'user@tempr.email';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'user@tempr.email'\\G\" xenforo"
    },
    {
        "email": "info@domain2.com",
        "elv_status": "valid",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "yes"
    },
    {
        "email": "xyz@domain1.com",
        "elv_status": "email_disabled",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "no",
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'xyz@domain1.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'xyz@domain1.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'xyz@domain1.com'\\G\" xenforo"
    },
    {
        "email": "abc@domain1.com",
        "elv_status": "email_disabled",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "yes",
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'abc@domain1.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'abc@domain1.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'abc@domain1.com'\\G\" xenforo"
    },
    {
        "email": "123@domain1.com",
        "elv_status": "email_disabled",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "no",
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = '123@domain1.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = '123@domain1.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = '123@domain1.com'\\G\" xenforo"
    },
    {
        "email": "pop@domain1.com",
        "elv_status": "email_disabled",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "no",
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'pop@domain1.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pop@domain1.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'pop@domain1.com'\\G\" xenforo"
    },
    {
        "email": "pip@domain1.com",
        "elv_status": "email_disabled",
        "elv_status_code": "",
        "elv_free_email": "no",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_free_email": "no",
        "mv_disposable_email": "no",
        "mv_free_email_api": "no",
        "mv_role_api": "no",
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'pip@domain1.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'pip@domain1.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'pip@domain1.com'\\G\" xenforo"
    },
    {
        "email": "user@gmail.com",
        "elv_status": "valid",
        "elv_status_code": "",
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": "yes",
        "mv_role_api": "no"
    },
    {
        "email": "op999@gmail.com",
        "elv_status": "email_disabled",
        "elv_status_code": "",
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "invalid",
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": "yes",
        "mv_role_api": "no",
        "elv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';\" xenforo",
        "elv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';",
        "elv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'op999@gmail.com'\\G\" xenforo",
        "mv_xf_sql": "mysql -e \"UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';\" xenforo",
        "mv_xf_sql_batch": "UPDATE xf_user SET user_state = 'email_bounce' WHERE email = 'op999@gmail.com';",
        "mv_xf_sql_user": "mysql -e \"SELECT user_id, username, email, user_group_id, secondary_group_ids, message_count, register_date, last_activity, user_state, is_moderator, is_admin, is_banned FROM xf_user WHERE email = 'op999@gmail.com'\\G\" xenforo"
    },
    {
        "email": "user@yahoo.com",
        "elv_status": "valid",
        "elv_status_code": "",
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": "yes",
        "mv_role_api": "no"
    },
    {
        "email": "user1@outlook.com",
        "elv_status": "valid",
        "elv_status_code": "",
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": "yes",
        "mv_role_api": "no"
    },
    {
        "email": "user2@hotmail.com",
        "elv_status": "valid",
        "elv_status_code": "",
        "elv_free_email": "yes",
        "elv_disposable_email": "no",
        "mv_status": "ok",
        "mv_free_email": "yes",
        "mv_disposable_email": "no",
        "mv_free_email_api": "yes",
        "mv_role_api": "no"
    }
]

real    0m41.260s
user    0m0.581s
sys     0m0.033s
```

## API Merge Filters

For API merged results, if you ran the commands and piped them into a `results.txt` file, you can then query and filter them using `jq` tool for different combinations of `elv_status` and `mv_status` values as follows:

1. Find good emails, filter good emails where `elv_status` is "valid" and `mv_status` is "ok":
```bash
cat results.txt | jq '.[] | select(.elv_status == "valid" and .mv_status == "ok")'
```

```
cat results.txt | jq '.[] | select(.elv_status == "valid" and .mv_status == "ok")'
{
  "email": "user+to@domain1.com",
  "elv_status": "valid",
  "elv_status_code": "",
  "elv_free_email": "no",
  "elv_disposable_email": "no",
  "mv_status": "ok",
  "mv_free_email": "no",
  "mv_disposable_email": "no",
  "mv_free_email_api": "no",
  "mv_role_api": "no"
}
{
  "email": "info@domain2.com",
  "elv_status": "valid",
  "elv_status_code": "",
  "elv_free_email": "no",
  "elv_disposable_email": "no",
  "mv_status": "ok",
  "mv_free_email": "no",
  "mv_disposable_email": "no",
  "mv_free_email_api": "no",
  "mv_role_api": "yes"
}
{
  "email": "user@gmail.com",
  "elv_status": "valid",
  "elv_status_code": "",
  "elv_free_email": "yes",
  "elv_disposable_email": "no",
  "mv_status": "ok",
  "mv_free_email": "yes",
  "mv_disposable_email": "no",
  "mv_free_email_api": "yes",
  "mv_role_api": "no"
}
{
  "email": "user1@outlook.com",
  "elv_status": "valid",
  "elv_status_code": "",
  "elv_free_email": "yes",
  "elv_disposable_email": "no",
  "mv_status": "ok",
  "mv_free_email": "yes",
  "mv_disposable_email": "no",
  "mv_free_email_api": "yes",
  "mv_role_api": "no"
}
{
  "email": "user2@hotmail.com",
  "elv_status": "valid",
  "elv_status_code": "",
  "elv_free_email": "yes",
  "elv_disposable_email": "no",
  "mv_status": "ok",
  "mv_free_email": "yes",
  "mv_disposable_email": "no",
  "mv_free_email_api": "yes",
  "mv_role_api": "no"
}
```

2. Find bad emails, filter emails where `elv_status` is "invalid" and `mv_status` is "invalid":
```bash
cat results.txt | jq '.[] | select(.elv_status == "invalid" and .mv_status == "invalid")'
```

3. Filter emails where `elv_status` is "valid" but `mv_status` is not "ok":

This filters for if you ran MillionVerifier bulk API and there is a bug in `unknown` status, you can use EmailListVerify API to double check it's status.

```bash
cat results.txt | jq '.[] | select(.elv_status == "valid" and .mv_status != "ok")'
```
```
cat results.txt | jq '.[] | select(.elv_status == "valid" and .mv_status != "ok")'
{
  "email": "user@yahoo.com",
  "elv_status": "valid",
  "elv_status_code": "",
  "elv_free_email": "yes",
  "elv_disposable_email": "no",
  "mv_status": "unknown",
  "mv_free_email": "yes",
  "mv_disposable_email": "no",
  "mv_free_email_api": "yes",
  "mv_role_api": "no"
}
```

4. Filter emails where `elv_status` is not "valid" but `mv_status` is "ok":

This would be the reverse of previous check, to double check EmailListVerify's result against MillionVerifier

```bash
cat results.txt | jq '.[] | select(.elv_status != "valid" and .mv_status == "ok")'
```

5. Filter bad emails where `elv_status` is not "valid" and `mv_status` is not "ok":
```bash
cat results.txt | jq '.[] | select(.elv_status != "valid" and .mv_status != "ok")'
```

6. Filter emails where `elv_status` is "disposable" and `mv_status` is "disposable":
```bash
cat results.txt | jq '.[] | select(.elv_status == "disposable" and .mv_status == "disposable")'
```

7. Filter emails where `elv_status` is "unknown" and `mv_status` is "unknown":
```bash
cat results.txt | jq '.[] | select(.elv_status == "unknown" and .mv_status == "unknown")'
```

8. Filter emails where either `elv_status` or `mv_status` is "invalid":
```bash
cat results.txt | jq '.[] | select(.elv_status == "invalid" or .mv_status == "invalid")'
```

9. Filter emails where either `elv_status` or `mv_status` is "disposable":
```bash
cat results.txt | jq '.[] | select(.elv_status == "disposable" or .mv_status == "disposable")'
```

10. Filter emails where either `elv_status` or `mv_status` is "unknown":
```bash
cat results.txt | jq '.[] | select(.elv_status == "unknown" or .mv_status == "unknown")'
```

11. Filter emails where `elv_status` is "valid" and `mv_status` is "unknown":

This filters for if you ran MillionVerifier bulk API and there is a bug in `unknown` status, you can use EmailListVerify API to double check it's status.

```
cat results.txt | jq '.[] | select(.elv_status == "valid" and .mv_status == "unknown")'
```
```
cat results.txt | jq '.[] | select(.elv_status == "valid" and .mv_status == "unknown")'
{
  "email": "user@yahoo.com",
  "elv_status": "valid",
  "elv_status_code": "",
  "elv_free_email": "yes",
  "elv_disposable_email": "no",
  "mv_status": "unknown",
  "mv_free_email": "yes",
  "mv_disposable_email": "no",
  "mv_free_email_api": "yes",
  "mv_role_api": "no"
}
```

These `jq` queries cover various combinations of `elv_status` and `mv_status` values, allowing you to filter the `results.txt` file based on different criteria. You can adjust the specific status values in the queries according to your needs and the available status values in the `results.txt` file.

Remember to replace `results.txt` with the actual path to your file if it's located in a different directory.

# Cloudflare HTTP Forward Proxy Cache With KV Storage

`validate_emails.py` script's [EmailListVerify](https://centminmod.com/emaillistverify) and [Zerobounce](https://centminmod.com/zerobounce) per email check API routines has been updated to support a custom Cloudflare HTTP forward proxy Worker cache configuration which can take the script's API request and forward it to EmailListVerify's API endpoint. The Cloudflare Worker script will then save the API result into Cloudflare KV storage on their edge servers and save with a date timestamp. This can potentially reduce your overall [EmailListVerify](https://centminmod.com/emaillistverify) per email verification costs if you need to run `validate_emails.py` a few times back to back bypassing having to need to call `validate_emails.py` API itself.

`validate_emails.py` script added `-apicache`, `-apicachettl`, `-apicache-purge` and `-apicachecheck` arguments:

- `-apicache` this sets the Cloudflare Worker's `cacheKey` and allows extending caching to other API providers in future. For now supported value are `emaillistverify` and `zerobounce` which will end up creating the `cacheKey` in Worker `const cacheKey = ${apiCache}:${email};` for lookups etc.
- `-apicachecheck` takes `count` or `list` or `purge` option to query the Cloudflare KV storage cache to count number of cached entries or list the entries themselves or purge Cloudflare CDN/KV stores in cache.
- `-apicache-purge` will purge Cloudflare CDN/KV cache when `-apicachecheck` set to `purge` options to query the 
- `-apicachettl` this sets the cache TTL duration in seconds for how long Cloudflare CDN/KV stores in cache. Default value is 300s or 5mins

One usage case for this would be if you verify a list of 1,000 email addresses and in a short amount of time (i.e. 24hrs) have an additional 500 email addresses added to the email list to total 1,500 emails. Then if you had originally verified the list with `-apicache` and `-apicachettl 172800` parameters, and did a second verification run, the original 1,000 email addresses would of already been stored in Cloudflare CDN and/or Cloudflare Worker KV storage caching so would not result in an API request/costs. Leaving only the 500 new email addresses resulting in an API request/costs. However, you would get a full JSON formatted result output for all 1,500 email addresses - ready for further processing/manipulation etc. Of course, you can also just have 2 separate verification runs for 1,000 emails and then for 500 emails and have 2 separate JSON formatted result outputs to work with which you can combine etc.

Another usage case is in case of email duplication in your lists. If you have the email address referenced multiple times in an email list, then using  `-apicache` and `-apicachettl 172800` parameters like parameters for first verification run, would allow it process and detect duplicates on second run via the Cloudflare CDN / Worker KV cached return results rather than make needless duplicate API request calls which would cost money. A lot of email verification providers offer email list deduplication as a built in feature while others offer it for additional costs. But with Cloudflare CDN / Worker KV caching in place, you wouldn't need to worry about the email verification provider's support for email deduplication. Thus saving your money $$$$$!

Examples to illustrate how the Cloudflare HTTP forward proxy caching KV worker workers for testing email address `hnyfmw5@canadlan-drugs.com`

Via direct EmailListVerify API call returns email address status = `unknown`

```
curl -s "https://apps.emaillistverify.com/api/verifyEmail?secret=$elvkey&email=hnyfmw5@canadlan-drugs.com&timeout=15"
unknown
```

Uncached usual run via the script usual result response would be `unknown`

```
time python validate_emails.py -f user@domain1.com -e hnyfmw5@canadlan-drugs.com -tm all -api emaillistverify -apikey $elvkey
[
    {
        "email": "hnyfmw5@canadlan-drugs.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "no"
    }
]

real    0m2.600s
user    0m0.279s
sys     0m0.020s
```

Via Cloudflare HTTP forward proxy caching KV worker with `-apicachettl 120` argument set returns email address status = `unknown` reducing time to return the result from 2.6s to 0.397s

```
time python validate_emails.py -f user@domain1.com -e hnyfmw5@canadlan-drugs.com -tm all -api emaillistverify -apikey $elvkey -apicache emaillistverify -apicachettl 120
[
    {
        "email": "hnyfmw5@canadlan-drugs.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "unknown",
        "disposable_email": "no"
    }
]

real    0m0.397s
user    0m0.294s
sys     0m0.025s
```

Log inspection

```
cat email_verification_log_2024-05-08_15-08-05.log | tail -3
2024-05-08 15:08:06,816 - INFO - Checking cache for email: hnyfmw5@canadlan-drugs.com
2024-05-08 15:08:07,047 - INFO - Cache check response status code: 200
2024-05-08 15:08:07,047 - INFO - Cache result: unknown
```

Testing Cloudflare HTTP forward proxy caching KV worker directly

```
curl -s "https://cfcachedomain.com/?email=hnyfmw5@canadlan-drugs.com&cachettl=120"
unknown
```

Cloudflare HTTP forward proxy caching KV worker console logged

```
[DEBUG] Incoming request: https://cfcachedomain.com/?email=hnyfmw5@canadlan-drugs.com&cachettl=120
[DEBUG] Email: hnyfmw5@canadlan-drugs.com
[DEBUG] Cache Key: emaillistverify:hnyfmw5@canadlan-drugs.com
[DEBUG] Cache TTL: 120
[DEBUG] Cache Check: null
[DEBUG] API URL: https://apps.emaillistverify.com/api/verifyEmail?secret=APIKEY&email=hnyfmw5@canadlan-drugs.com&timeout=15
[DEBUG] Response from Cloudflare CDN cache: Hit
[DEBUG] Skipping KV cache update as response is served from Cloudflare CDN cache
[DEBUG] Returning final response with headers: {"cache-control":"max-age=120","content-type":"text/plain"}
```

Check how many KV storage cached email result entries there are

```
curl -s "https://cfcachedomain.com/?apicachecheck=count" | jq -r
{
  "count": 1
}
```

Query the actual KV storage cached email address entries including the cache age

```
curl -s "https://cfcachedomain.com/?apicachecheck=list" | jq -r
[
  {
    "email": "hnyfmw5@canadlan-drugs.com",
    "result": "unknown",
    "timestamp": 1715175271549,
    "age": 16,
    "ttl": 120
  }
]
```

Query the KV storage cache entries count via `-apicachecheck count`

```
time python validate_emails.py -f user@domain1.com -e hnyfmw5@canadlan-drugs.com -tm all -api emaillistverify -apikey $elvkey -apicache emaillistverify -apicachettl 120 -apicachecheck count

API cache count: 1
```

Query the KV storage cache entries listings via `-apicachecheck list`

```
time python validate_emails.py -f user@domain1.com -e hnyfmw5@canadlan-drugs.com -tm all -api emaillistverify -apikey $elvkey -apicache emaillistverify -apicachettl 120 -apicachecheck list

API cache list:
{'email': 'hnyfmw5@canadlan-drugs.com', 'result': 'unknown', 'timestamp': 1715175271549, 'age': 16, 'ttl': 120}
```

Cloudflare KV storage entries

| Key                                        | Value                                           |
|--------------------------------------------|--------------------------------------------------|
| emaillistverify:hnyfmw5@canadlan-drugs.com  | {"result":"unknown","timestamp":1715175271549,"ttl":120}  |

## ZeroBounce Cloudflare Cache Support

For ZeroBounce per email check API `-api zerobounce -apikey_zb $zbkey` with Cloudflare Cache `-apicache zerobounce -apicachettl 900`

```
time python validate_emails.py -f user@domain1.com -e hnyfmw@canadlan-drugs.com -tm all -api zerobounce -apikey_zb $zbkey -tm all -apicache zerobounce -apicachettl 900

[
    {
        "email": "hnyfmw@canadlan-drugs.com",
        "status": "invalid",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    }
]

real    0m0.777s
user    0m0.253s
sys     0m0.034s
```

Log inspection

```
cat $(ls -Art | tail -3 | grep 'email_verification')

2024-05-11 11:28:05,131 - INFO - Cache result: {'address': 'hnyfmw@canadlan-drugs.com', 'status': 'invalid', 'sub_status': 'no_dns_entries', 'free_email': False, 'did_you_mean': None, 'account': 'hnyfmw', 'domain': 'canadlan-drugs.com', 'domain_age_days': '2026', 'smtp_provider': '', 'mx_found': 'false', 'mx_record': '', 'firstname': None, 'lastname': None, 'gender': None, 'country': None, 'region': None, 'city': None, 'zipcode': None, 'processed_at': '2024-05-11 10:37:39.035'}
```

Cloudflare KV storage entries

| Key                                        | Value                                           |
|--------------------------------------------|--------------------------------------------------|
| zerobounce:hnyfmw@canadlan-drugs.com  | {"result":{"address":"hnyfmw@canadlan-drugs.com","status":"invalid","sub_status":"no_dns_entries","free_email":false,"did_you_mean":null,"account":"hnyfmw","domain":"canadlan-drugs.com","domain_age_days":"2026","smtp_provider":"","mx_found":"false","mx_record":"","firstname":null,"lastname":null,"gender":null,"country":null,"region":null,"city":null,"zipcode":null,"processed_at":"2024-05-11 11:39:24.133"},"timestamp":1715427564270,"ttl":900}  |

## Cloudflare Cache Purge Support

Add support to purge Cloudflare KV storage via `-apicache-purge -apicachecheck purge` when combined with `-apicache emaillistverify` 

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -apicache-purge -apicache emaillistverify -apicachecheck purge

Cache purged successfully
```

Run with `-apicachecheck count` to report the number of cached entries in Cloudflare KV storage after cache purge:

```
python validate_emails.py -f user@domain1.com -l emaillist.txt -apicache-purge -apicache emaillistverify -apicachecheck count

API cache count: {'bulk_count': 0, 'email_count': 0}
```

## EmailListVeirfy Bulk File API Cloudflare Cache Support

Add Cloudflare cache support to [EmailListVerify's](https://centminmod.com/emaillistverify) bulk file API routine via `-apicache emaillistverify -apicachettl 120` and ran it 3 times - for unprimed cache and primed cached run for 2nd and 3rd runs to compare time to completion. Cloudflare HTTP forward proxy KV cache Worker reduced times from 40.771s to 2.078s.

| Run      | Compeletion Time |
|----------|--------------|
| 1st Bulk File API Run uncached | 40.771s       |
| 2nd Bulk File API Run cached  | 2.292s       |
| 3rd Bulk File API Run cached  | 2.078s       |


Example 1st [EmailListVerify](https://centminmod.com/emaillistverify) bulk API unprimed Cloudflare Worker cache run timed:

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -api emaillistverify -apikey $elvkey -apibulk emaillistverify -apicache emaillistverify -apicachettl 120 -tm all
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

real    0m40.771s
user    0m0.469s
sys     0m0.019s
```

Inspecting logs

```
cat $(ls -Art | tail -3 | grep 'email_verification')                                             
2024-05-10 09:59:28,893 - INFO - File MIME type: text/plain
2024-05-10 09:59:29,050 - INFO - Request data: {'filename': 'emaillist_20240510095928.txt'}
2024-05-10 09:59:29,050 - INFO - File data: {'file_contents': ('emaillist_20240510095928.txt', <_io.BufferedReader name='emaillist.txt'>, 'text/plain')}
2024-05-10 09:59:30,258 - INFO - File uploaded successfully. File ID: 2408431
2024-05-10 09:59:30,538 - INFO - File processing in progress. Status: progress
2024-05-10 09:59:36,056 - INFO - File processing in progress. Status: progress
2024-05-10 09:59:41,604 - INFO - File processing in progress. Status: progress
2024-05-10 09:59:47,171 - INFO - File processing in progress. Status: progress
2024-05-10 09:59:52,687 - INFO - File processing in progress. Status: progress
2024-05-10 09:59:57,959 - INFO - File processing in progress. Status: progress
2024-05-10 10:00:03,519 - INFO - File processing in progress. Status: progress
2024-05-10 10:00:08,927 - INFO - File processing completed. Retrieving results from: https://files-elv.s3.eu-central-1.amazonaws.com/2024-05/5b1ab4d47750dd66625245e1a0645328f93e8abc_all.csv
2024-05-10 10:00:09,259 - INFO - Results file downloaded: emaillistverify_results_1715335169.csv
2024-05-10 10:00:09,456 - INFO - Bulk file results cached in Cloudflare
2024-05-10 10:00:09,456 - INFO - Results retrieved successfully. Total lines: 15
```

Example 2nd [EmailListVerify](https://centminmod.com/emaillistverify) bulk API primed Cloudflare Worker cache run timed:

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -api emaillistverify -apikey $elvkey -apibulk emaillistverify -apicache emaillistverify -apicachettl 120 -tm all
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
        "status": "invalid_syntax",
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
        "status": "ok",
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
        "email": "user@gmail.com",
        "status": "ok",
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
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    }
]

real    0m2.292s
user    0m0.533s
sys     0m0.022s
```

Log inspection shows bulk file API upload process was skipped as all email addresses in bulk file `-l emaillist.txt` passed on command line were found in Cloudflare cache.

```
cat $(ls -Art | tail -3 | grep 'email_verification')                                             
2024-05-10 10:34:03,308 - INFO - File MIME type: text/plain
2024-05-10 10:34:05,392 - INFO - All email results found in cache. Skipping file upload.
```

Example 3rd [EmailListVerify](https://centminmod.com/emaillistverify) bulk API primed Cloudflare Worker cache run timed:

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -api emaillistverify -apikey $elvkey -apibulk emaillistverify -apicache emaillistverify -apicachettl 120 -tm all
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
        "status": "invalid_syntax",
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
        "status": "ok",
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
        "email": "user@gmail.com",
        "status": "ok",
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
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    }
]

real    0m2.078s
user    0m0.527s
sys     0m0.038s
```

Log inspection shows bulk file API upload process was skipped as all email addresses in bulk file `-l emaillist.txt` passed on command line were found in Cloudflare cache.

```
cat $(ls -Art | tail -3 | grep 'email_verification')                                             
2024-05-10 10:34:10,862 - INFO - File MIME type: text/plain
2024-05-10 10:34:12,724 - INFO - All email results found in cache. Skipping file upload.
```

## EmailListVerify API Check Times: Regular vs Cached

This table presents a side-by-side comparison of the time taken for regular and cached EmailListVerify API checks. Testing [Cloudflare HTTP Forward Proxy Cache With KV Storage](#cloudflare-http-forward-proxy-cache-with-kv-storage) with [EmailListVerify](https://centminmod.com/emaillistverify) per email check API. Ran the same 15 emails `emaillist.txt` test and timed the 3 runs each.

First cached email verification checks are slower due to priming the cache overhead. While subseqent cached runs were much faster compared to uncached regular email verification checks.

| Run      | Regular Time | Cached Time |
|----------|--------------|-------------|
| 1st Run  | 5.102s       | 5.437s      |
| 2nd Run  | 3.146s       | 1.029s      |
| 3rd Run  | 3.248s       | 0.944s      |


Regular uncached run 1

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api emaillistverify -apikey $elvkey
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
        "status": "invalid",
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

real    0m5.102s
user    0m0.299s
sys     0m0.026s
```

Regular uncached run 2

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api emaillistverify -apikey $elvkey
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
        "status": "invalid",
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

real    0m3.146s
user    0m0.303s
sys     0m0.022s
```

Regular uncached run 3

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api emaillistverify -apikey $elvkey
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
        "status": "invalid",
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

real    0m3.248s
user    0m0.296s
sys     0m0.030s
```

Cached run 1

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api emaillistverify -apikey $elvkey -apicache emaillistverify -apicachettl 120
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
        "status": "invalid_syntax",
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
        "status": "ok",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "ok",
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
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    }
]

real    0m5.437s
user    0m2.339s
sys     0m0.044s
```

Cached run 2

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api emaillistverify -apikey $elvkey -apicache emaillistverify -apicachettl 120
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
        "status": "invalid_syntax",
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
        "status": "ok",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "ok",
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
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    }
]

real    0m1.029s
user    0m2.373s
sys     0m0.043s
```

Cached run 3

```
time python validate_emails.py -f user@domain1.com -l emaillist.txt -tm all -api emaillistverify -apikey $elvkey -apicache emaillistverify -apicachettl 120
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
        "status": "invalid_syntax",
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
        "status": "ok",
        "status_code": null,
        "free_email": "no",
        "disposable_email": "no"
    },
    {
        "email": "user@gmail.com",
        "status": "ok",
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
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user1@outlook.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    },
    {
        "email": "user2@hotmail.com",
        "status": "ok",
        "status_code": null,
        "free_email": "yes",
        "disposable_email": "no"
    }
]

real    0m0.944s
user    0m2.316s
sys     0m0.050s
```

# PHP Wrapper

Created a simplistic PHP wrapper script to call `validate_emails.py` from that can test multiple email verification API providers as well as local non-API tests for a single inputted email address. The PHP wrapper will also time how long it takes to return an email verification check's JSON response. This was tested on a PHP 8.3.6 based [Centmin Mod LEMP stack server](https://centminmod.com).

| Provider | Completion Time |
| --- | --- |
| Local (Non-API) | 0.516784s |
| [EmailListVerify](https://centminmod.com/emaillistverify) | 2.96s |
| [MillionVerifier](https://centminmod.com/millionverifier) | 0.84s |
| [CaptainVerify](https://centminmod.com/captainverify) | 21.96s |
| [Proofy.io](https://centminmod.com/proofy) | 31.77s (API error, ran out of credits) |
| [MyEmailVerifier](https://centminmod.com/myemailverifier) | 3.09s |
| [Zerobounce](https://centminmod.com/zerobounce) | 0.68s |
| [Reoon](https://centminmod.com/reoon) | 0.72s |
| [Bouncify](https://centminmod.com/bouncify) | 1.04s |

First one is local non-API test = 0.516784s

![Email verification PHP Wrapper script](screenshots/php-wrappers/validate_email_php_wrapper_00.png)

[EmailListVerify](https://centminmod.com/emaillistverify) = 2.96s

![Email verification PHP Wrapper script](screenshots/php-wrappers/validate_email_php_wrapper_01.png)

[MillionVerifier](https://centminmod.com/millionverifier) = 0.84s

![Email verification PHP Wrapper script](screenshots/php-wrappers/validate_email_php_wrapper_02.png)

[CaptainVerify](https://centminmod.com/captainverify) = 21.96s

![Email verification PHP Wrapper script](screenshots/php-wrappers/validate_email_php_wrapper_03.png)

[Proofy.io](https://centminmod.com/proofy) = 31.77s for api_error ran out of credits right now

![Email verification PHP Wrapper script](screenshots/php-wrappers/validate_email_php_wrapper_08.png)

[MyEmailVerifier](https://centminmod.com/myemailverifier) = 3.09s

![Email verification PHP Wrapper script](screenshots/php-wrappers/validate_email_php_wrapper_04.png)

[Zerobounce](https://centminmod.com/zerobounce) = 0.68s

![Email verification PHP Wrapper script](screenshots/php-wrappers/validate_email_php_wrapper_05.png)

[Reoon](https://centminmod.com/reoon) = 0.72s

![Email verification PHP Wrapper script](screenshots/php-wrappers/validate_email_php_wrapper_06.png)

[Bouncify](https://centminmod.com/bouncify) = 1.04s

![Email verification PHP Wrapper script](screenshots/php-wrappers/validate_email_php_wrapper_07.png)


## PHP Wrapper With Cloudflare Cache And S3 Store Support

Updated PHP wrapper script with single and multiple email support via `validate_emails.py` per email verification routines and added `validate_emails.py` supported [Cloudflare Cache](##cloudflare-http-forward-proxy-cache-with-kv-storage) (enabled for [EmailListVerify](https://centminmod.com/emaillistverify) and [Zerobounce](https://centminmod.com/zerobounce)) and also support for [S3 storage](#s3-storage-support) to store email verification results to either Amazon AWS S3 or Cloudflare R2 object storage buckets.

Note: Timings reported include time for S3 storage - in this case saving to Cloudflare R2 bucket

Single email address [EmailListVerify](https://centminmod.com/emaillistverify) runs including a debug run

![Email verification PHP Wrapper script with Cloudflare Cache & S3 storage support](screenshots/php-wrappers/validate_email_php_wrapper_multi-style2-cloudflare-cache-s3-02.png)

![Email verification PHP Wrapper script with Cloudflare Cache & S3 storage support](screenshots/php-wrappers/validate_email_php_wrapper_multi-style2-cloudflare-cache-s3-02a.png)

![Email verification PHP Wrapper script with Cloudflare Cache & S3 storage support](screenshots/php-wrappers/validate_email_php_wrapper_multi-style2-cloudflare-cache-s3-02b.png)

Multiple email addresses [EmailListVerify](https://centminmod.com/emaillistverify) runs including a debug run

![Email verification PHP Wrapper script with Cloudflare Cache & S3 storage support](screenshots/php-wrappers/validate_email_php_wrapper_multi-style2-cloudflare-cache-s3-02c.png)

![Email verification PHP Wrapper script with Cloudflare Cache & S3 storage support](screenshots/php-wrappers/validate_email_php_wrapper_multi-style2-cloudflare-cache-s3-02d.png)

![Email verification PHP Wrapper script with Cloudflare Cache & S3 storage support](screenshots/php-wrappers/validate_email_php_wrapper_multi-style2-cloudflare-cache-s3-02e.png)
