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
        format_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """A file has been detected that has been determined to be potentially malicious. A case has been opened. 
Case link: {0}
Event Name: 
Description: {2}
Source URL: {3}
Target Server IP: {4}
Suspicious File Path: {5}"""

    # parameter list for template variable replacement
    parameters = [
        "container:url",
        "container:name",
        "container:description",
        "filtered-data:Fix_Source:condition_1:artifact:*.cef.sourceDnsDomain",
        "filtered-data:Fix_Address:condition_1:artifact:*.cef.destinationAddress",
        "filtered-data:Fix_Path:condition_1:artifact:*.cef.filePath",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    send_email_1(container=container)

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')

    # collect data for 'send_email_1' call
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    parameters.append({
        'from': "edu-labserver@splunk.com",
        'to': "bwalden@splunk.com",
        'cc': "",
        'bcc': "",
        'subject': "New Case Created",
        'body': formatted_data_1,
        'attachments': "",
        'headers': "",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_1")

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