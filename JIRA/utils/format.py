# format.py

"""Base class to format the desciption & comment section in Jira tickets. """

import logging
from collections import OrderedDict


# ---------------------------------------------------------------------------------------------------------------------
class Format(object):
    """Base class to format the desciption & comment section in Jira tickets. """

    def status(self, content, color):
        """Method to add the custom status label. """

        color_dict = {
            'purple': '65331960-4815-4a7e-b92f-8f8c461c757d'
            , 'green': '745d4a6d-0c4d-4cea-a021-9651f432d95a'
        }
        status_dict = {
            'type': 'status',
            'attrs': {
                'text': str(content),
                'color': color.lower(),
                'localId': color_dict[color.lower()],
                'style': ''
            }
        }
        return status_dict
    
    def text(self, content, link=False):
        """Method to add text form. """

        text_dict = {
            'type': 'text',
            'text': str(content)
        }
        if bool(link):
            href_dict = {"type": "link", "attrs": {"href": content}}
            text_dict.update({"marks": [href_dict]})
        return text_dict

    def mention(self, account_id):
        """Method to mention targer user accounts. """

        mention_dict = {
            'type': 'mention',
            'attrs': {
                'id': str(account_id),
                'accessLevel': ''
            }
        }
        return mention_dict

    def hard_break(self):
        """Method to add hard breaks (new lines) in panel format. """

        json_dict = {
            'type': 'hardBreak'
        }
        return json_dict

    def paragraph(self, content):
        """Method to add paragraph type. """

        paragraph_dict = {
            'type': 'paragraph',
            'content': content
        }
        return paragraph_dict
    
    def media(self, media_id):
        """Method to add media type. """

        media_dict = {
            "type": "mediaGroup",
            "content": [
                {
                    "type": "media",
                    "attrs": {
                        "type": "file",
                        "id": media_id,
                        "collection": ""
                    }
                }
            ]
        }
        return media_dict

    def panel_heading(self, content, level=2):
        """Method to add header title in panel format. """

        content_list = [{'type': 'text', 'text': content}]
        heading_dict = {
            'type': 'heading'
            , 'attrs': {'level': int(level)}
            , 'content': content_list
        }
        return heading_dict
        
    def panel_paragraph(self, content_dict, panel_break):
        """Method to add paragraph type in panel format. """

        content_list = []
        whitespace = ' ' * 5
        delimiter = ' : '
        counter = 0
        for key, value in content_dict.items():
            content_list.append(self.status(content=key, color='purple'))
            content_list.append(self.text(content=delimiter))
            content_list.append(self.status(content=value, color='green'))
            content_list.append(self.text(content=whitespace))
            counter += 1
            # insert new line after 3 entries & remove last line
            if counter % 5 == 0 and counter != len(content_dict.keys()) and panel_break:
                content_list.append(self.hard_break())
        paragraph_dict = {
            'type': 'paragraph'
            , 'content': content_list
        }
        return paragraph_dict

    def panel(self, header, content_dict, panel_type, panel_break=True):
        """Method to add panel type in Jira ticket description/comment section. """

        heading_dict = self.panel_heading(content=header)
        paragraph_dict = self.panel_paragraph(content_dict=content_dict, panel_break=panel_break)
        content_list = [heading_dict, paragraph_dict]
        panel_dict = {
            'type': 'panel',
            'attrs': {
                'panelType': panel_type
            },
            "content": content_list
        }
        return panel_dict

    def description(self, metrics_dict, media_id_list):
        """Method to add/update Jira ticket decription section with formatted content. """

        logging.debug('Add/update Jira ticket decription section with formatted content')
        content_list = []
        header = 'Latest Snyk Scan Result'
        
        if bool(metrics_dict['vulnerabilities']):
            panel_type = 'error'
            status = 'VULNERABILITIES FOUND'
        else:
            panel_type = 'success'
            status = 'NO VULNERABILITIES FOUND'
        
        # maintaining the dictionary insertion order
        content_dict = OrderedDict()
        tuple_list = [
            ('SCAN DATE', metrics_dict['scan_date']), 
            ('SCAN TYPE', metrics_dict['scan_type']), 
            ('SERVICE', metrics_dict['service']), 
            ('STATUS', status)
        ]
        if metrics_dict['scan_type'] == 'snyk-container':
            tuple_list.append(('REGION', 'production-in'))
        else:
            tuple_list.append(('BRANCH', metrics_dict['branch']))

        for tuple in tuple_list:
            content_dict[tuple[0]] = tuple[1]
        panel_dict = self.panel(header=header, content_dict=content_dict, panel_type=panel_type, panel_break=False)
        content_list.append(panel_dict)
        
        if bool(metrics_dict['vulnerabilities']):
            header = 'Scan reports for troubleshooting'
            heading_dict = self.panel_heading(content=header)
            content_list.append(heading_dict)

            for media_id in media_id_list:
                paragraph_dict = self.paragraph(content=[self.text(content='File:')])
                content_list.append(paragraph_dict)
                media_dict = self.media(media_id=media_id)
                content_list.append(media_dict)
            
            if metrics_dict['scan_type'] == 'snyk-open-source':
                header = 'Snyk links for assessing package health and vulnerabilities'
                heading_dict = self.panel_heading(content=header)
                content_list.append(heading_dict)

                text = 'Snyk Advisor: '
                link = 'https://snyk.io/advisor'
                paragraph_dict = self.paragraph(content=[self.text(content=text), self.text(content=link, link=True)])
                content_list.append(paragraph_dict)

                text = 'Snyk Vulnerability Database: '
                link = 'https://security.snyk.io'
                paragraph_dict = self.paragraph(content=[self.text(content=text), self.text(content=link, link=True)])
                content_list.append(paragraph_dict)

        description_dict = {
            'fields': {
                'description': {
                    'version': 1,
                    'type': 'doc',
                    'content': content_list
                }
            }
        }
        
        logging.debug('Formatted description content: \n{0}'.format(description_dict))
        return description_dict

    def comment(self, metrics_dict, account_id):
        """Method to add/update Jira ticket comment section with formatted content. """

        logging.debug('Add/update Jira ticket comment section with formatted content')
        content_list = []
        
        if bool(metrics_dict['vulnerabilities']):
            message = 'Snyk vulnerabilities found in the latest scan. Please see ticket description for the vulnerability details.'
        else:
            message = 'No Snyk vulnerabilities found in the latest scan. Closing this ticket.'
        
        paragraph_dict = self.paragraph(content=[self.text(content=message)])
        content_list.append(paragraph_dict)
        
        comment_dict = {
            'body': {
                'version': 1,
                'type': 'doc',
                'content': content_list
            },
            'visibility': None
        }

        logging.debug('Formatted comment content: \n{0}'.format(comment_dict))
        return comment_dict

    def payload_create_ticket(self, fields):
        """Method to generate Jira REST payload with required fields. """

        logging.debug('Generate Jira REST payload with required fields: {0}'.format(fields))
        payload = {
            "fields": {
                "project": {
                    "key": "INFRA"
                },
                "summary": fields['summary'],
                "description": ".",
                "issuetype": {
                    "name": "Bug"
                },
                "customfield_10070": fields['service'],
                "labels": [
                    "devops", 
                    "security", 
                    "snyk"
                ],
                "assignee": {
                    "accountId": fields['assignee']
                }
            }
        }
        return payload

    def payload_transition_ticket(self, transition_id):
        """Method to generate Jira REST payload required for transitioning ticket. """

        logging.debug('Generate Jira REST payload for transitioning ticket states')
        payload = {
            "transition": {
                "id": int(transition_id)
            }
        }
        return payload
