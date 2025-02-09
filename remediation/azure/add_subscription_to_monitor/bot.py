import logging
from sonrai import gql_loader
import sys
import re
import time
from datetime import datetime

def run(ctx):
    # Get the ticket data from the context
    ticket = ctx.config.get('data').get('ticket')
    currentTime = round(time.time() * 1000)
    now = datetime.now()
    dateStamp = now.strftime("%Y-%m-%dT%H:%M:%S")

    # Load searches:
    gql = gql_loader.queries()

    # Create GraphQL client
    graphql_client = ctx.graphql_client()

    tenant_id = None
    collector_srn = None

    # Loop through each of the custom fields and set the values that we need
    for customField in ticket.get('customFields'):
        if 'value' not in customField.keys():
            continue

        name = customField['name']
        value = customField['value']

        if name == 'Tenant':
            tenant_id = value
        elif name == 'Collector':
            collector_srn = value

    #GraphQL query for the subscriptions
    queryAllSubscriptions = gql['subscriptions.gql']

    variables = ( '{"tenant": "' + tenant_id +'"}')
    logging.info('Searching for all subscriptions for tenant id : {}'.format(tenant_id))
    r_subscriptions = graphql_client.query(queryAllSubscriptions, variables)

    # GraphQL to get monitored subscriptions on collector already
    queryPlatformSubscriptions = gql['platformCloudAccounts.gql']

    variables = ( '{"srn": "'+collector_srn+'"}')
    logging.info('Searching for already monitored subscriptions on collector: {}'.format(collector_srn))
    r_platform_subscriptions = graphql_client.query(queryPlatformSubscriptions, variables)

    # mutation to add Azure Subscription
    mutation_add_subscription = gql['createPlatformcloudaccount.gql']

    # mutation for adding a tag to the Subscription so it won't get processed again.
    mutation_add_tag  = gql['addTag.gql']

    subscription_list = None
    for resourceId in r_subscriptions['Subscriptions']['items']:
        # step through all subscriptions to see if it is already added to a collector
        add_subscription = True
        subscription_srn = resourceId['srn']
        try:
            subscriptionToAdd = re.sub("\/subscriptions\/", "", resourceId['resourceId'])
        except TypeError as e:
            logging.error("Encountered an invalid or null resourceId for subscription resourceID:'{}' srn:'{}'".format(resourceId, subscription_srn))
            logging.error(e)
            continue

        # check if the subscriptionToAdd is already added
        for existing_subscriptions in r_platform_subscriptions['PlatformCloudAccounts']['items']:
            subscriptionId = existing_subscriptions['blob']['subscriptionId']
            if subscriptionToAdd == subscriptionId:
                add_subscription = False

        if add_subscription:
            # Subscription doesn't exist on the collector. Adding it here
            variables =  ('{"account": {"containedByAccount":' +
                                         '{"add": "' + collector_srn + '"},' +
                                     '"cloudType": "azure",' +
                                     '"blob": {'  +
                                         '"subscriptionId": "' + subscriptionToAdd +'",'+
                                         '"tenantId": "' + tenant_id + '",' +
                                         '"runDateTime": ' + str(currentTime) +
                                         '}'+
                                     '}'+
                         '}')
            
            
            if subscription_list is None:
                subscription_list = "- " + subscriptionToAdd
            else:
                subscription_list = subscription_list + "\\n- " + subscriptionToAdd

            logging.info('Adding Subscription {}'.format(subscriptionToAdd))
            r_add_subscription = graphql_client.query(mutation_add_subscription, variables)
            variables = ('{"key":"SonraiBotAdded","value":"'+ dateStamp + '","srn":"'+subscription_srn+'"}')
            r_add_tag = graphql_client.query(mutation_add_tag, variables)
            exit(0)
            
    if subscription_list is not None:
        # build comment for ticket
        comment = "The following subscriptions have been added for monitoring:\\n" + subscription_list
        gql_loader.add_ticket_comment(ctx, comment)

    gql_loader.snooze_ticket(ctx, hours=2)
    