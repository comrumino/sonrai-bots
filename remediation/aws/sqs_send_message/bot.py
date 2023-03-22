# https://github.com/sonraisecurity/sonrai-bots
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs.html
# https://github.com/sonraisecurity/sonrai-public-assets/tree/main/utilities/api
import logging
import traceback

import sonrai.platform.aws.arn
import time
import requests
import json


DEFAULT_QUEUE = 'sonrai-sqs-bot'
DEFAULT_ROLE = f'{DEFAULT_QUEUE}-producer'
DEFAULT_SQS_REGION = 'us-east-1'
LOG_GROUP = DEFAULT_ROLE
LOG_STREAM = 'default'


def enrich(ctx):
    result = {}
    # Get the ticket data from the context
    ticket = ctx.config.get('data').get('ticket')
    ticket_srn = ticket.get('srn')
    result['ticket_url'] = f'https://app.sonraisecurity.com/App/TicketDetails?srn={ticket_srn}'

    # Create GraphQL client
    graphql_client = ctx.graphql_client()

    # query ticket endpoint for swimlanes
    queryTicketsForSwimlanes = ('''
    {
      Tickets(
        where: {
          srn: {
            op: EQ
            value: "'''+ticket_srn+'''"
          }
        }
      ) {
        items {
          swimlaneSRNs
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
    ''')
    variables = {}
    logging.info('Searching for swimlanes of ticket {}'.format(ticket_srn))
    r_ticket_swimlanes = graphql_client.query(queryTicketsForSwimlanes, variables)
    ticket = r_ticket_swimlanes['Tickets']['items'][0]

    result['policy'] = ticket.get('policy', {}).get('title')
    result['policy_type'] = ticket.get('policy', {}).get('controlPolicyMetaTypes', []).join('/')
    result['severityCategory'] = ticket['severityCategory']
    result['status'] = ticket['status']

    result['resource_name'] = ticket['resourceName']
    result['resource_id'] = str(sonrai.platform.aws.arn.parse(ctx.resource_id))
    swimlaneList = [s for s in r_ticket_swimlanes['Tickets']['items'][0]['swimlaneSRNs'] if 'Global' not in s]

    # get resourceIDs of the Swimlanes of the tickets
    querySwimlanes = ('''
    query Swimlanes ($swimlaneSRNs: [String]){Swimlanes
        (where:
               {srn: {op:IN_LIST, values:$swimlaneSRNs}}
        )
      {
            items {
                  srn
                  title
        }}}
    ''')

    # Build the variable to use the query

    variables = json.dumps({"swimlaneSRNs": swimlaneList})
    r_swimlanes = graphql_client.query(querySwimlanes, variables)
    titles = set([sw['title'] for sw in r_swimlanes['Swimlanes']['items']])
    # get integrations
    queryIntegrations = '''
        query getIntegrations {
          Integrations {
            items {
              srn
              title
              type
              createdBy
              email { emailList { email } }
              configs {
                srn
                createdBy
                assignment {
                  srn
                  SwimlaneSRN
                }
                email {
                  actionTypes
                  emailFilter {
                    ticketKey
                    ticketType
                    allKeys
                    allTypes
                  }
                }
              }
            }
          }
        }
    '''
    integrations = graphql_client.query(queryIntegrations, {})
    _items = [i for i in list(integrations['Integrations']['items'] or []) if i['title'] in titles]
    swimlane_emails = {i['title']: i.get('email', {}).get('emailList', ['null']).join(';') for i in _items}
    result['swimlane_emails'] = swimlane_emails
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
    _res = client_sqs.get_queue_url(QueueName=DEFAULT_QUEUE)
    queue_url = _res['QueueUrl']
    try:
        sqs_msg = {}
        sqs_msg = enrich(ctx)
        cw_log(client_logs, json.dumps(sqs_msg))
    except Exception:
        cw_log(client_logs, traceback.format_exc())
    try:
        res = client_sqs.send_message(QueueUrl=queue_url, MessageBody=json.dumps(sqs_msg))
        cw_log(client_logs, json.dumps(res))
    except Exception:
        cw_log(client_logs, traceback.format_exc())
