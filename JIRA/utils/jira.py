# jira.py

"""Base class to create & update Jira tickets. """

import base64
import logging
import re

from utils.generic import Generic


# ---------------------------------------------------------------------------------------------------------------------
class Jira(object):
    """Base class to create & update Jira tickets. """

    def __init__(self, config, username, token):
        """Base class to create & update Jira tickets. """

        self.config = config
        self.generic = Generic()
        self.username = username
        self.token = token

    def generate_header(self):
        """Method to generate header section for Jira REST API calls. """

        logging.debug('Generate header section for Jira REST API calls')
        credential = bytes('{0}:{1}'.format(self.username, self.token), encoding='utf8')
        token = base64.b64encode(credential).decode('utf-8')
        headers = {
            'Content-Type': 'application/json'
            , 'Authorization': 'Basic {0}'.format(token)
        }
        return headers

    def create(self, payload):
        """Method to create a new Jira Cloud ticket with required fields. """

        logging.debug('Create new Jira Cloud ticket with required fields')
        create_url = '{0}/rest/api/2/issue'.format(self.config['jira_url'])
        headers = self.generate_header()
        response = self.generic.request(call_type='POST', url=create_url, json=payload, headers=headers)
        if response.status_code != 201:
            raise ValueError('Jira ticket creation failed.\nStatus code: {0}.\nResponse: {1}'.format(
                response.status_code, response.text))
        ticket_id = response.json()['key']
        return ticket_id

    def description(self, ticket_id, payload):
        """Method to add/update the Jira ticket decription section. """

        logging.debug('Add/update description section of Jira Cloud ticket: {0}'.format(ticket_id))
        description_url = '{0}/rest/api/3/issue/{1}'.format(self.config['jira_url'], ticket_id)
        headers = self.generate_header()
        response = self.generic.request(call_type='PUT', url=description_url, json=payload, headers=headers)
        if response.status_code != 204:
            raise ValueError('Failed to add/update description section of Jira ticket: {0}.\nStatus code: {1}.\nResponse: {2}'.format(
                ticket_id, response.status_code, response.text))

    def comment(self, ticket_id, payload):
        """Method to add/update Jira ticket comment section. """

        logging.debug('Add/update Jira ticket comment section of Jira Cloud ticket: {0}'.format(ticket_id))
        comment_url = '{0}/rest/api/3/issue/{1}/comment'.format(self.config['jira_url'], ticket_id)
        headers = self.generate_header()
        response = self.generic.request(call_type='POST', url=comment_url, json=payload, headers=headers)
        if response.status_code != 201:
            raise ValueError('Failed to add/update comment section of Jira ticket: {0}.\nStatus code: {1}.\nResponse: {2}'.format(
                ticket_id, response.status_code, response.text))
    
    def transition(self, ticket_id, payload):
        """Method to transition Jira ticket to required workflow state. """

        logging.debug('Transition Jira ticket: {0} to required workflow state'.format(ticket_id))
        transition_url = '{0}/rest/api/3/issue/{1}/transitions'.format(self.config['jira_url'], ticket_id)
        headers = self.generate_header()
        response = self.generic.request(call_type='POST', url=transition_url, json=payload, headers=headers)
        if response.status_code != 204:
            raise ValueError('Failed to transition Jira ticket: {0} to required state.\nStatus code: {1}.\nResponse: {2}'.format(
                ticket_id, response.status_code, response.text))

    def watcher(self, ticket_id, payload):
        """Method to add watchers to Jira ticket. """

        logging.debug('Adding watcher to Jira ticket: {0}'.format(ticket_id))
        watcher_url = '{0}/rest/api/3/issue/{1}/watchers'.format(self.config['jira_url'], ticket_id)
        headers = self.generate_header()
        response = self.generic.request(call_type='POST', url=watcher_url, data=payload, headers=headers)
        if response.status_code != 204:
            raise ValueError('Failed to add watcher to Jira ticket: {1}.\nStatus code: {1}.\nResponse: {2}'.format(
                ticket_id, response.status_code, response.text))

    def fields(self, ticket_id):
        """Method to fetch the current field values of Jira ticket. """

        logging.debug('Get current field values of Jira ticket: {0}'.format(ticket_id))
        status_url = '{0}/rest/api/3/issue/{1}'.format(self.config['jira_url'], ticket_id)
        headers = self.generate_header()
        response = self.generic.request(call_type='GET', url=status_url, headers=headers)
        if response.status_code != 200:
            raise ValueError('Failed to get the current field values of Jira ticket: {0}.\nStatus code: {1}.\nResponse: {2}'.format(
                ticket_id, response.status_code, response.text))
        logging.debug('Jira ticket: {0} field values: {1}'.format(ticket_id, response.json()))
        return response.json()

    def add_attachment(self, ticket_id, files):
        """Method to add attachments to existing Jira ticket. """

        logging.debug('Adding new attachment to Jira Cloud ticket: {0}'.format(ticket_id))
        attachment_url = '{0}/rest/api/3/issue/{1}/attachments'.format(self.config['jira_url'], ticket_id)
        headers = self.generate_header()
        del headers['Content-Type']
        headers.update({'X-Atlassian-Token': 'no-check'})
        response = self.generic.request(call_type='POST', url=attachment_url, files=files, headers=headers)
        if response.status_code != 200:
            raise ValueError('Failed to add attachments to Jira ticket: {0}.\nStatus code: {1}.\nResponse: {2}'.format(
                ticket_id, response.status_code, response.text))
        
        logging.debug('Fetching the file media ID')
        content_url = response.json()[0]['content']
        del headers['X-Atlassian-Token']
        response = self.generic.request(call_type='HEAD', url=content_url, headers=headers)
        response_headers = response.headers
        logging.debug('Response headers: {0}'.format(response_headers))
        media_id = re.findall(r'/file/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/binary', response_headers['Location'])[0]
        return media_id

    def delete_attachment(self, attachment_id, ticket_id):
        """Method to delete existing attachments in Jira ticket. """

        logging.debug('Deleting new attachment: {0} in Jira Cloud ticket: {1}'.format(attachment_id, ticket_id))
        attachment_url = '{0}/rest/api/3/attachment/{1}'.format(self.config['jira_url'], attachment_id)
        headers = self.generate_header()
        response = self.generic.request(call_type='DELETE', url=attachment_url, headers=headers)
        if response.status_code != 204:
            raise ValueError('Failed to delete attachments to Jira ticket: {0}.\nStatus code: {1}.\nResponse: {2}'.format(
                ticket_id, response.status_code, response.text))
