"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'promote_to_case_1' block
    promote_to_case_1(container=container)

    return

def promote_to_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('promote_to_case_1() called')

    phantom.promote(container=container, template="Data Breach")
    Fix_Source(container=container)

    return

def Fix_Source(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Fix_Source() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceDnsDomain", "!=", ""],
        ],
        name="Fix_Source:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Fix_Address(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Fix_Address(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Fix_Address() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="Fix_Address:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Fix_Path(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def Fix_Path(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Fix_Path() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.filePath", "!=", ""],
        ],
        name="Fix_Path:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        Get_Country_Name(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """A file has been detected that has been determined to be potentially malicious. A case has been opened. 
Case link: {0}
Event Name: 
Description: {2}
Source URL: {3}
Target Server IP: {4}
Suspicious File Path: {5}
Origin Country: {6}"""

    # parameter list for template variable replacement
    parameters = [
        "container:url",
        "container:name",
        "container:description",
        "filtered-data:Fix_Source:condition_1:artifact:*.cef.sourceDnsDomain",
        "filtered-data:Fix_Address:condition_1:artifact:*.cef.destinationAddress",
        "filtered-data:Fix_Path:condition_1:artifact:*.cef.filePath",
        "Get_Country_Name:custom_function:countryName",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    format_2(container=container)

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    custom_function_2__container_email = json.loads(phantom.get_run_data(key='custom_function_2:container_email'))
    # collect data for 'send_email_1' call
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    parameters.append({
        'body': formatted_data_1,
        'from': "edu-labserver@splunk.com",
        'attachments': "",
        'to': custom_function_2__container_email,
        'cc': "",
        'bcc': "",
        'headers': "",
        'subject': "New Case Created",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_1")

    return

def Get_Country_Name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('Get_Country_Name() called')
    input_parameter_0 = ""

    Get_Country_Name__countryName = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    
    data = phantom.get_object(key='country_name_Email_Notify', container_id=container['id'])
	
    Get_Country_Name__countryName = data[0]['value']['value']
    
    # clear object db
    phantom.clear_object(key='country_name_Email_Notify',container_id=container['id'])

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='Get_Country_Name:countryName', value=json.dumps(Get_Country_Name__countryName))
    format_1(container=container)

    return

def get_data_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_data_1() called')

    # collect data for 'get_data_1' call
    formatted_data_1 = phantom.get_format_data(name='format_2')

    parameters = []
    
    # build parameters list for 'get_data_1' call
    parameters.append({
        'headers': "",
        'location': formatted_data_1,
        'verify_certificate': False,
    })

    phantom.act("get data", parameters=parameters, assets=['local'], callback=custom_function_2, name="get_data_1")

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_2() called')
    
    template = """/rest/ph_user/?_filter_username=%22{0}%22"""

    # parameter list for template variable replacement
    parameters = [
        "container:owner",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    get_data_1(container=container)

    return

def custom_function_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('custom_function_2() called')
    results_data_1 = phantom.collect2(container=container, datapath=['get_data_1:action_result.data.*.response_body'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    custom_function_2__container_email = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    custom_function_2__container_email = results_data_1[0][0]['data'][0]['email']

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='custom_function_2:container_email', value=json.dumps(custom_function_2__container_email))
    send_email_1(container=container)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return