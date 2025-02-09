# https://github.com/sonraisecurity/sonrai-bots
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs.html
# https://github.com/sonraisecurity/sonrai-public-assets/tree/main/utilities/api
import logging
import traceback

import sonrai.platform.aws.arn
import time
import json


DEFAULT_QUEUE = 'sonrai-sqs-bot'
DEFAULT_ROLE = f'{DEFAULT_QUEUE}-producer'
DEFAULT_SQS_REGION = 'us-east-1'
LOG_GROUP = DEFAULT_ROLE
LOG_STREAM = 'default'


def enrich(client_logs, ctx):
    try:
        result = {
            'policy': None,
            'policy_type': None,
            'severityCategory': None,
            'ticket_url': None,
            'resource_name': None,
            'resource_id': str(sonrai.platform.aws.arn.parse(ctx.resource_id)),
            'swimlane_emails': None
        }
        # Get the ticket data from the context
        ticket = ctx.config.get('data').get('ticket')
        ticket_srn = ticket.get('srn')
        result['ticket_url'] = f'https://app.sonraisecurity.com/App/TicketDetails?srn={ticket_srn}'

        # Create GraphQL client
        graphql_client = ctx.graphql_client()

        # query ticket endpoint for swimlanes
        queryTicketsForSwimlanes = '''
            query getTickets($ticket_srn: String) {
              Tickets(where: { srn: { op: EQ, value: $ticket_srn } }) {
                items {
                  swimlanes {
                    title
                    srn
                  }
                  account
                  firstSeen
                  lastSeen
                  severityCategory
                  resourceName
                  resourceTypeFriendlyName
                  status
                  policy {
                    title
                    controlPolicyMetaTypes
                  }
                }
              }
            }
        '''
        logging.info('Searching for swimlanes of ticket {}'.format(ticket_srn))
        r_ticket_swimlanes = graphql_client.query(queryTicketsForSwimlanes, {'ticket_srn': ticket_srn})
        try:
            ticket = r_ticket_swimlanes['Tickets']['items'][0]
            result['policy'] = ticket.get('policy', {}).get('title')
            result['policy_type'] = '/'.join(ticket.get('policy', {}).get('controlPolicyMetaTypes', []))
            result['severityCategory'] = ticket['severityCategory']
        except Exception:
            cw_log(client_logs, traceback.format_exc())
            return result

        # Build the variable to use the query
        result['resource_name'] = ticket['resourceName']
        result['account_id'] = ticket['account']
        result['last_seen'] = ticket['lastSeen']
        titles = [s['title'] for s in ticket['swimlanes']]
        result['swimlane_emails'] = {t: None for t in titles}
        # get integrations
        queryIntegrations = '''
            query getIntegrations($swimlanes: [String]) {
              Integrations(
                where: {
                  title: { op: IN_LIST, values: $swimlanes }
                  type: { op: EQ, value: "EMAIL" }
                }
              ) {
                items {
                  srn
                  title
                  type
                  email {
                    emailList {
                      email
                    }
                  }
                }
              }
            }
        '''
        integrations = graphql_client.query(queryIntegrations, {'swimlanes': titles})
        integrations = integrations['Integrations']['items'] or []
        for i in integrations:
            _flat_email_list = [u['email'] for u in i['email']['emailList']]
            result['swimlane_emails'][i['title']] = ';'.join(_flat_email_list)
        return result
    except Exception:
        cw_log(client_logs, traceback.format_exc())
        return result


def cw_log(client, msg):
    try:
        event_log = {
            'logGroupName': LOG_GROUP,
            'logStreamName': LOG_STREAM,
            'logEvents': [
                {
                    'timestamp': int(round(time.time() * 1000)),
                    'message': str(msg)
                }
            ],
        }
        response = client.describe_log_streams(logGroupName=LOG_GROUP, logStreamNamePrefix=LOG_STREAM)
        if 'uploadSequenceToken' in response['logStreams'][0]:
            event_log.update({'sequenceToken': response['logStreams'][0]['uploadSequenceToken']})
        response = client.put_log_events(**event_log)
        return True
    except Exception:
        return False


def run(ctx):
    client_sqs = ctx.get_client().get('sqs', region_name=DEFAULT_SQS_REGION)
    client_logs = ctx.get_client().get('logs', region_name=DEFAULT_SQS_REGION)
    try:
        client_logs.create_log_stream(logGroupName=LOG_GROUP, logStreamName=LOG_STREAM)
    except Exception:
        pass

    # SQS
    try:
        _res = client_sqs.get_queue_url(QueueName=DEFAULT_QUEUE)
        queue_url = _res['QueueUrl']
        sqs_msg = enrich(client_logs, ctx)
        res = client_sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps(sqs_msg))
        cw_log(client_logs, json.dumps(res))
    except Exception:
        cw_log(client_logs, traceback.format_exc())
