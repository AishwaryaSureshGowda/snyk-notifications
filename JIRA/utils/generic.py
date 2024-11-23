# generic.py

"""Base class with generic utilities. """

import datetime
import logging
import requests
import time
from requests.exceptions import (
    HTTPError
    , ConnectionError
    , Timeout
    , TooManyRedirects
    , RetryError
    , RequestException
)

requests.packages.urllib3.disable_warnings()


# ---------------------------------------------------------------------------------------------------------------------
class Generic(object):
    """Base class with generic utilities. """

    def __init__(self):
        """Base class with generic utilities. """

        self.session = requests.session()

    def request(self, call_type, retries=5, poll_interval=30, **request_param):
        """Method to send & receive HTTP(s) response using remote request call with retry support. """

        param_dict = request_param
        if not bool(param_dict.get('timeout')):
            param_dict.update({'timeout': 300})
        if not bool(param_dict.get('verify')):
            param_dict.update({'verify': False})
        
        # do not print the creds in log file
        request_dict = param_dict.copy()
        del request_dict['headers']
        logging.debug('Request dict: {0}'.format(request_dict))
        
        # default counter value
        counter = 0
        while True:
            try:
                logging.debug("Making remote request API call")
                if call_type.upper() == 'GET':
                    response = self.session.get(**param_dict)
                elif call_type.upper() == 'POST':
                    response = self.session.post(**param_dict)
                elif call_type.upper() == 'PUT':
                    response = self.session.put(**param_dict)
                elif call_type.upper() == 'HEAD':
                    response = self.session.head(**param_dict)
                elif call_type.upper() == 'DELETE':
                    response = self.session.delete(**param_dict)
                else:
                    raise ValueError('Call type: {0} not supported by requests module'.format(call_type))
                if not response.ok:
                    self.log('Status code: {0}'.format(response.status_code))
                    self.log('Response body: {0}'.format(response.text))
                # raise exception in case of HTTP 4xx & 5xx error response
                response.raise_for_status()
                break
            except HTTPError as e:
                logging.error('[HTTPError] Invalid HTTP response.')
                # 503 HTTP error is due to network flakiness - retry instead of raising exceptions
                if response.status_code != 503:
                    raise
            except Timeout as e:
                logging.warning('[TimeoutError] Request timed out while trying to connect to remote URL.\n{0}'.format(str(e)))
            except ConnectionError as e:
                logging.warning('[ConnectionError] Error in connecting to remote URL due to network issues.\n{0}'.format(str(e)))
            except TooManyRedirects as e:
                logging.error('[TooManyRedirectsError] Request has exceeded the max configured number of redirection.')
                raise
            except RequestException as e:
                logging.error('[RequestExceptionError] Generic exception occurred while handling request call.')
                raise
            counter += 1
            if counter <= retries:
                # padding time between request calls
                logging.debug('Waiting for recovery time of {0} seconds between retries'.format(poll_interval))
                time.sleep(poll_interval)
                logging.info('[{0}] Retrying Connection..'.format(counter))
            else:
                raise RetryError('[RetryError] Failed to connect. Exceeded max retries for request call.')
        logging.debug('Successfully fetched response from remote request call.')
        return response

    def log(self, text):
        """Method to print log to console output with current timestamp in UTC format. """

        current_time = datetime.datetime.now(datetime.UTC).strftime("%d-%m-%Y %I:%M:%S %p UTC")
        print('[%s] %s' % (current_time, text), flush=True)
