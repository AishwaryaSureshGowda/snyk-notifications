# execute.py

"""This module is used to create & update Jira cloud tickets in an automated manner. """

import argparse
import json
import os
import logging
import sys
import traceback

# custom utils
from utils.generic import Generic
from utils.jira import Jira
from utils.format import Format


# ---------------------------------------------------------------------------------------------------------------------
class ScrutJira(object):
    """Base class to create & update Jira cloud tickets in an automated manner. """

    def __init__(self, username, token, jira_store, metadata):
        """Base class to create & update Jira cloud tickets in an automated manner. """

        # initiate utils
        self.generic = Generic()
        self.format = Format()
        self.config = self.get_config()
        self.jira = Jira(config=self.config, username=username, token=token)
        
        # start execution
        metrics = self.scan_metrics(metadata_file=metadata)
        self.process_jira_ticket(metrics=metrics, store_file=jira_store)

    def get_config(self):
        """Method to get config data. """

        try:
            self.generic.log('Get configuration data')
            config_file_name = 'config.json'
            config_file_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), config_file_name)
            with open(config_file_path, 'r') as file:
                config_dict = json.load(file)
            logging.debug('Config dict: {0}'.format(config_dict))
        except Exception:
            self.generic.log('GetConfigError: \n{0}'.format(str(traceback.format_exc())))
            sys.exit(1)
        return config_dict
    
    def scan_metrics(self, metadata_file):
        """Method to fetch Snyk vulnerability scan metrics. """

        try:
            self.generic.log('Extracting Snyk vulnerability scan metrics from metadata file')
            with open(metadata_file, 'r') as file:
                scan_dict = json.load(file)
            metrics_dict = {
                'scan_date': scan_dict['scan_date']
                , 'scan_type': scan_dict['scan_type']
                , 'service': scan_dict['service']
                , 'report_dir': scan_dict['report_dir']
                , 'vulnerabilities': scan_dict.get('vulnerabilities')
                , 'branch': 'master'
            }
            self.generic.log('Scan metrics:\n{0}'.format(json.dumps(metrics_dict, indent=3)))
        except Exception:
            self.generic.log('ScanMetricsError: \n{0}'.format(str(traceback.format_exc())))
            sys.exit(1)
        return metrics_dict
    
    def create_ticket(self, metrics):
        """Method to create a new Jira cloud ticket with required fields. """
        
        self.generic.log('Creating new Jira ticket')
        
        scan_type = metrics['scan_type']
        service = metrics['service']
        
        if scan_type == 'snyk-open-source':
            scan_summary = 'Open Source Vulnerability'
        elif scan_type == 'snyk-source-code':
            scan_summary = 'Source Code Vulnerability'
        elif scan_type == 'snyk-container':
            scan_summary = 'Container Vulnerability'
        else:
            scan_summary = None
        
        summary = 'Snyk | {0} | {1}'.format(service, scan_summary)
        fields = {
            'summary': summary
            , 'service': service
            , 'assignee': self.config['user_id']['manjunath@scrut.io']
        }
        payload = self.format.payload_create_ticket(fields=fields)
        ticket_id = self.jira.create(payload=payload)
        
        self.generic.log('Jira ticket: {0}/browse/{1}'.format(self.config['jira_url'], ticket_id))
        
        self.generic.log('Adding watchers to Jira ticket: {0}'.format(ticket_id))
        watcher_list = self.config['watcher']
        for watcher in watcher_list:
            try:
                user_id = self.config['user_id'][watcher]
                payload = json.dumps("{0}".format(user_id))
                self.jira.watcher(ticket_id=ticket_id, payload=payload)
            except Exception:
                self.generic.log('{0}'.format(str(traceback.format_exc())))
        
        return ticket_id

    def update_description_comment(self, ticket_id, metrics):
        """Method to update the description and comment section of Jira ticket. """

        response = self.jira.fields(ticket_id=ticket_id)
        
        # deleting existing attachment files
        for x in response['fields']['attachment']:
            attachment_id = x['id']
            self.generic.log('Deleting attachment with ID: {0}'.format(attachment_id))
            self.jira.delete_attachment(attachment_id=attachment_id, ticket_id=ticket_id)
        
        # add new attachment files only if any vulnerability exists
        media_id_list = []
        if bool(metrics['vulnerabilities']):
            report_dir = metrics['report_dir']
            for report_file in sorted(os.listdir(report_dir), reverse=True):
                report_file_path = report_dir + os.sep + report_file
                self.generic.log('Adding new file attachment: {0}'.format(report_file_path))
                files = {
                    'file': (report_file, open(report_file_path, 'rb'), 'multipart/form-data')
                }
                media_id = self.jira.add_attachment(ticket_id=ticket_id, files=files)
                media_id_list.append(media_id)
            
        self.generic.log('Updating ticket description: {0}'.format(ticket_id))
        payload = self.format.description(metrics_dict=metrics, media_id_list=media_id_list)
        self.jira.description(ticket_id=ticket_id, payload=payload)

        self.generic.log('Adding new comment in ticket: {0}'.format(ticket_id))
        account_id = response['fields']['assignee']['accountId']
        payload = self.format.comment(metrics_dict=metrics, account_id=account_id)
        self.jira.comment(ticket_id=ticket_id, payload=payload)

    def transition_ticket(self, ticket_id, transition_id):
        """Method to transition Jira cloud ticket to desired state. """

        self.generic.log('Transitioning ticket: {0} to state: {1}'.format(ticket_id, transition_id))
        payload = self.format.payload_transition_ticket(transition_id=transition_id)
        self.jira.transition(ticket_id=ticket_id, payload=payload)

    def process_jira_ticket(self, metrics, store_file):
        """Method to process Jira cloud ticket. """

        try:
            self.generic.log('Processing Jira cloud ticket')
            ticket_id = self.check_ticket(metrics=metrics, store_file=store_file)
            vulnerabilities = metrics['vulnerabilities']

            if bool(vulnerabilities):
                if not bool(ticket_id):
                    # CONDITION-1: create new jira ticket - if vulnerabilities exist and tracking jira ticket does not exist
                    new_ticket_id = self.create_ticket(metrics=metrics)
                    self.update_description_comment(ticket_id=new_ticket_id, metrics=metrics)
                    self.store_ticket(ticket_id=new_ticket_id, metrics=metrics, store_file=store_file)
                else:
                    # CONDITION-2: update existing jira ticket - if vulnerabilities exist and tracking jira ticket also exists
                    self.update_description_comment(ticket_id=ticket_id, metrics=metrics)
                    status_id = int(self.jira.fields(ticket_id=ticket_id)['fields']['status']['id'])
                    if status_id == self.config['status_id']['done']:
                        self.transition_ticket(ticket_id=ticket_id, transition_id=self.config['transition_id']['to_do'])
            else:
                if not bool(ticket_id):
                    # CONDITION-3: ignore - if there are no vulnerabilities and tracking jira ticket does not exist
                    self.generic.log('Nothing to process. No vulnerabilities found & corresponding Jira ticket does not exist')
                    return
                status_id = int(self.jira.fields(ticket_id=ticket_id)['fields']['status']['id'])
                if status_id != self.config['status_id']['done']:
                    # CONDITION-4: close existing ticket - if there are no vulnerabilities and tracking jira ticket is not in closed state
                    self.update_description_comment(ticket_id=ticket_id, metrics=metrics)
                    self.transition_ticket(ticket_id=ticket_id, transition_id=self.config['transition_id']['done'])
                    self.generic.log('Successfully closed Jira cloud ticket')
                else:
                    # CONDITION-5: ignore - if there are no vulnerabilities and tracking jira ticket is already closed
                    self.generic.log('Nothing to process. Jira cloud ticket is already in closed state')
        except Exception:
            self.generic.log('ProcessTicketError: \n{0}'.format(str(traceback.format_exc())))
            sys.exit(1)

    def check_ticket(self, metrics, store_file):
        """Method to check if Jira ticket already exists for Snyk vulnerabilities. """

        try:
            scan_type = metrics['scan_type'].upper()
            service = metrics['service'].upper()
            self.generic.log('Checking for existing Jira ticket')
            # read file contents
            delimiter = ' : '
            with open(store_file, 'r') as file:
                line_list = file.readlines()
            ticket_id = None
            for line in line_list:
                if line.rstrip() == '':
                    # ignore empty lines
                    continue
                content_list = line.split(delimiter)
                file_scan_type = content_list[0].upper()
                file_service = content_list[1].upper()
                if scan_type == file_scan_type and service == file_service:
                    ticket_id = content_list[2].rstrip()
                    self.generic.log('Ticket already exists: {0}'.format(ticket_id))
        except Exception:
            raise ValueError('CheckTicketError: \n{0}'.format(str(traceback.format_exc())))
        return ticket_id

    def store_ticket(self, ticket_id, metrics, store_file):
        """Method to store the Jira cloud ticket in store file. """

        try:
            self.generic.log('Storing Jira cloud ticket: {0} in store file: {1}'.format(ticket_id, store_file))
            scan_type = metrics['scan_type'].upper()
            service = metrics['service'].upper()
            delimiter = ' : '
            content = '{0}{1}{2}{3}{4}'.format(scan_type, delimiter, service, delimiter, ticket_id)
            with open(store_file, 'a') as file:
                file.write('{0}\n'.format(content))
            self.generic.log('Current store file content:')
            with open(store_file, 'r') as file:
                print(file.read())
        except Exception:
            raise ValueError('StoreTicketError: \n{0}'.format(str(traceback.format_exc())))


# ---------------------------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    # file logger
    LOG_FILE = os.path.dirname(os.path.abspath(__file__)) + os.sep + 'jira.log'
    logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG)
    
    parser = argparse.ArgumentParser(description='Python module used to create & update Jira cloud tickets in an automated manner')
    parser.add_argument('--jira-username', type=str, help='Jira username', required=True)
    parser.add_argument('--jira-token', type=str, help='Jira API token', required=True)
    parser.add_argument('--jira-store', type=str, help='Jira ticket store file', required=True)
    parser.add_argument('--metadata', type=str, help='File with Snyk scan info', required=True)
    args = parser.parse_args()

    ScrutJira(username=args.jira_username, token=args.jira_token, jira_store=args.jira_store, metadata=args.metadata)
# --------------------------------------------------------------------------------------------------------------------
