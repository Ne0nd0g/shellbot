#! /usr/bin/env python

__author__ = 'Russel Van Tuyl'
__maintainer__ = "Russel Van Tuyl"
__email__ = "Russel.VanTuyl@gmail.com"
__version__ = "1.1"

import sqlite3
import datetime
import requests
import time
import ConfigParser
import msgpack
import sys
import os
import argparse
#################################################
#                   COLORS                      #
#################################################
note = "\033[0;0;33m[-]\033[0m"
warn = "\033[0;0;31m[!]\033[0m"
info = "\033[0;0;36m[i]\033[0m"
question = "\033[0;0;37m[?]\033[0m"
debug = "\033[0;0;31m[DEBUG]\033[0m"

ssb_root = os.path.dirname(os.path.realpath(__file__))
runTime = datetime.datetime.now()
sleepTime = 60
slackHook = None
teamsHook = None
botName = None
channel = None
empireDb = None
msfRpcHost = "127.0.0.1"
msfRpcPort = "55552"
msfRpcUser = "msf"
msfRpcPass = None
msfRpcToken = None
knownAgents = {"empire": [], "msf": []}

DEBUG = False
VERBOSE = False


def db_query(dbPath):
    """Query sqlite database"""

    agents = {}

    try:
        connection = sqlite3.connect(dbPath)
        rs = connection.execute("SELECT session_id, checkin_time, name, external_ip, internal_ip, username, hostname, "
                                "os_details, high_integrity, process_name, process_id FROM agents;")

        for r in rs:
            agents[r[0]] = {'checkin_time': r[1],
                            'session_id': r[0],
                            'name': r[2],
                            'external_ip': r[3],
                            "internal_ip": r[4],
                            "username": r[5],
                            "hostname": r[6],
                            "os_details": r[7],
                            "high_integrity": str(r[8]),
                            "process_name": r[9],
                            "process_id": r[10]
                            }

        connection.close()
    except sqlite3.OperationalError as e:
        print warn + "Error connecting to the database at %s" % dbPath
        print e

    return agents


def msf_rpc_request(payload):
    """Make HTTP POST Request to MSF RPC Interface"""

    url = "http://" + msfRpcHost + ":" + msfRpcPort + "/api/1.1"
    headers = {'content-type': 'binary/message-pack'}
    try:
        response = requests.post(url, data=payload, headers=headers, verify=False)
        return response
    except requests.exceptions.ConnectionError:
        print warn + "ShellBot will continue without Metasploit because it was unable to communicate with the RPC"\
                     " server at %s" % url
        print "\t" + info + "try 'load msgrpc` in your currently running Metasploit Instance"
        print "\t" + info + "Visit https://help.rapid7.com/metasploit/Content/api-rpc/getting-started-api.html for " \
                            "additional information"
        return None


def msf_rpc_get_temp_auth_token():
    """Get a temporary authentication token from the Metasploit RPC Server"""

    global msfRpcToken

    payload = msgpack.packb(["auth.login", msfRpcUser, msfRpcPass])
    response = msf_rpc_request(payload)

    if response is not None:
        if DEBUG:
            print debug + "MSF RPC auth.login response:\n\tHTTP Status Code: %s" % response.status_code
            if response.headers['Content-Type'] == "binary/message-pack":
                msf_rpc_message = msgpack.unpackb(response.content, use_list=False)
                print "\t" + debug + "MSF RPC Server Response: %s" % msf_rpc_message
                if 'error' in msf_rpc_message.keys():
                    print debug + "MSF RPC Error: %s" % msf_rpc_message['error_message']
            else:
                print "\t" + debug + "HTTP Server Response: %s" % response.content
        if response.status_code == 200:
            result = msgpack.unpackb(response.content, use_list=False)
            if 'error' in result.keys():
                print warn + "MSF RPC Error: %s" % result['error_message']
                print warn + "Quitting"
                sys.exit()
            elif 'token' in result.keys():
                msfRpcToken = result['token']


def msf_rpc_get_session_list():
    """Get a list of Meterpreter sessions"""

    payload = msgpack.packb(["session.list", msfRpcToken])
    response = msf_rpc_request(payload)
    result = msgpack.unpackb(response.content, use_list=False)

    if response.status_code == 200:
        return result
    else:
        return None


def send_new_agent_message_slack(agentType, payload):
    """Send New Agent Message to Slack"""

    if DEBUG:
        print debug + "New Slack agent message agent: %s, payload: %s" % (agentType, payload)

    text = "[+]New %s agent check in\n%s" % (agentType, payload)
    if agentType == "Meterpreter":
        json_payload = {"channel": channel, "username": "ShellBot", "text": text, "icon_emoji": ":metasploit:"}
    elif agentType == "Empire":
        json_payload = {"channel": channel, "username": "ShellBot", "text": text, "icon_emoji": ":empire:"}
    else:
        json_payload = {"channel": channel, "username": "ShellBot", "text": text}

    headers = {'content-type': 'application/json'}

    response = requests.post(slackHook, json=json_payload, headers=headers)

    if DEBUG:
        print debug + "%s" % response.text
        print debug + "%d" % response.status_code
    if response.status_code == 200:
        print "\033[0;0;92m[+]\033[0mNew %s agent check in successfully posted to Slack" % agentType
        print "\t" + note + "%s" % payload.replace("\n", ", ")
    else:
        print warn + "Message not posted to Slack. HTTP Status Code: %s" % response.status_code


def send_new_agent_message_teams(agentType, payload):
    """Send a Microsoft Teams Activity Card HTTP POST message to a web hook"""
    
    if teamsHook is None:
        print debug + "Teams hook not provided. Skipping."

    if DEBUG:
        print debug + "New Microsoft Teams agent message agent: %s, payload: %s" % (agentType, payload)

    json_payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": "[+]New %s agent check in" % agentType,
        "title": "[+]New %s agent check in" % agentType,
        "themeColor": "FF1000",
        "sections": [{"text": "I smell pwnage in the air..."}, {"facts": [{"name": "Agent Type", "value": agentType}]}]
    }

    for p in payload:
        json_payload["sections"][1]["facts"].append({"name": p, "value": payload[p]})
    headers = {'content-type': 'application/json'}

    response = requests.post(teamsHook, json=json_payload, headers=headers)

    if DEBUG:
        print debug + response.text
        print debug + "%d" % response.status_code
        print debug + "%s" % json_payload
    if response.status_code == 200:
        print "\033[0;0;92m[+]\033[0mNew %s agent check in successfully posted to Microsoft Teams" % agentType
        if agentType == "Empire":
            print "\t" + note + "Agent ID: %s, Checkin Time: %s" % (payload.get("session_id"),
                                                                    payload.get("checkin_time"))
        elif agentType == "Meterpreter":
            print "\t" + note + "Meterpreter UUID: %s, Info: %s" % (payload.get("uuid"),
                                                                    payload.get("info"))
    else:
        print warn + "Message not posted to Microsoft Teams. HTTP Status Code: %s" % response.status_code


def parse_config(configFile):
    """Parse the ShellBot configuration file and update global variables"""

    global sleepTime
    global slackHook
    global botName
    global channel
    global empireDb
    global msfRpcHost
    global msfRpcPort
    global msfRpcUser
    global msfRpcPass
    global teamsHook

    if VERBOSE:
        print note + "Parsing config file at %s" % configFile

    c = ConfigParser.ConfigParser()
    c.read(configFile)

    if c.has_section("slack"):
        if c.has_option("slack", "slackHook"):
            slackHook = c.get("slack", "slackHook")
        else:
            print warn + "Configuration file missing 'slackHook' parameter in 'slack' section"
            sys.exit(1)
        if c.has_option("slack", "botName"):
            botName = c.get("slack", "botName")
        else:
            print warn + "Configuration file missing 'botName' parameter in 'slack' section"
            sys.exit(1)
        if c.has_option("slack", "channel"):
            channel = c.get("slack", "channel")
        else:
            print warn + "Configuration file missing 'channel' parameter in 'slack' section"
            sys.exit(1)
    else:
        print warn + "Missing 'slack' section in configuration file"
        sys.exit(1)

    # This section can be missing, will use global variables instead
    if c.has_section("ShellBot"):
        if c.has_option("ShellBot", "sleepTime"):
            sleepTime = c.getint("ShellBot", "sleepTime")

    if c.has_section("empire"):
        if c.has_option("empire", "db"):
            e = c.get("empire", "db")
            if os.path.isfile(os.path.join(ssb_root, e)):
                empireDb = os.path.join(ssb_root, e)
            else:
                print warn + "ShellBot will continue without Empire because database was not found at %s" \
                             % os.path.join(ssb_root, e)
        else:
            print warn + "ShellBot will continue without Empire because database path not provided."
    else:
        print warn + "ShellBot will continue without Empire because configuration was not provided."

    if c.has_section("teams"):
        if c.has_option("teams", "teamsHook"):
            if c.get("teams", "teamsHook") != "https://outlook.office.com/webhook/<randomstuff>":
                teamsHook = c.get("teams", "teamsHook")
            else:
                print info + "Microsoft Teams Web Hook was not provided"

    if c.has_section("msf"):
        if c.has_option("msf", "msfRpcHost"):
            msfRpcHost = c.get("msf", "msfRpcHost")
        else:
            print warn + "ShellBot will continue without Metasploit Framework because the " \
                         "host was not provided"
        if c.has_option("msf", "msfRpcPort"):
            msfRpcPort = c.get("msf", "msfRpcPort")
        else:
            print warn + "ShellBot will continue without Metasploit Framework because the " \
                         "port was not provided"
        if c.has_option("msf", "msfRpcUser"):
            msfRpcUser = c.get("msf", "msfRpcUser")
        else:
            print warn + "ShellBot will continue without Metasploit Framework because the " \
                         "user was not provided"
        if c.has_option("msf", "msfRpcPass"):
            msfRpcPass = c.get("msf", "msfRpcPass")
        else:
            print warn + "ShellBot will continue without Metasploit Framework because the " \
                         "password was not provided"
    else:
        print warn + "ShellBot will continue without Metasploit because configuration was not provided."

    msf_rpc_get_temp_auth_token()


def check_empire_agents(db):
    """Check for new Empire agents"""

    global knownAgents

    agents = db_query(db)

    if DEBUG:
        print debug + "%s" % agents
    if VERBOSE:
        print info + "Currently checked in agents:"
        for a in agents:
            print "\t" + info + "Session ID: %s\t Checkin Time: %s" % (a, agents[a]['checkin_time'])
    for a in agents:
        checkin = datetime.datetime.strptime(agents[a]['checkin_time'], "%Y-%m-%d %H:%M:%S")
        if a not in knownAgents["empire"]:
            knownAgents["empire"].append(a)
            if checkin > runTime:
                msg = "Agent ID: %s\nCheckin Time: %s" % (agents[a]['session_id'], agents[a]['checkin_time'])
                send_new_agent_message_slack("Empire", msg)
                teams = {"session_id": agents[a]['session_id'], "checkin_time": agents[a]['checkin_time']}
                send_new_agent_message_teams("Empire", agents[a])


def check_msf_agents():
    """Check to see if there are any new meterpreter sessions"""
    if VERBOSE:
        print info + "Checking for new Meterpreter agents"
    msf_rpc_get_temp_auth_token()
    if msfRpcToken is not None:
        sessions_result = msf_rpc_get_session_list()
        if sessions_result is not None:
            for s in sessions_result:
                if DEBUG:
                    print debug + "Agent Information:\n%s" % sessions_result[s]
                if sessions_result[s]['uuid'] not in knownAgents['msf']:
                    knownAgents['msf'].append(sessions_result[s]['uuid'])
                    msg = "Agent: %s\nInfo: %s\nExploit: %s\nPayload: %s\n" % (sessions_result[s]['uuid'],
                                                                               sessions_result[s]['info'],
                                                                               sessions_result[s]['via_exploit'],
                                                                               sessions_result[s]['via_payload'])
                    send_new_agent_message_slack("Meterpreter", msg)
                    send_new_agent_message_teams("Meterpreter", sessions_result[s])


if __name__ == '__main__':

    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--debug', action='store_true', default=False, help="Enable debug output to console")
        parser.add_argument('-v', action='store_true', default=False, help="Enable verbose output to console")
        args = parser.parse_args()
        VERBOSE = args.v
        DEBUG = args.debug

        conf = os.path.join(ssb_root, "shellbot.conf")
        parse_config(conf)

        if (empireDb is not None) or (msfRpcToken is not None):
            print info + "ShellBot started..."
            while True:
                if empireDb is not None:
                    check_empire_agents(empireDb)
                if msfRpcToken is not None:
                    check_msf_agents()
                if VERBOSE:
                    print info + "Sleeping for %s seconds at %s" % (sleepTime, datetime.datetime.now())
                time.sleep(sleepTime)
        else:
            print warn + "Unable to locate or communicate with any C2 servers. Quitting"
            sys.exit(1)

    except KeyboardInterrupt:
        print "\n" + warn + "User Interrupt! Quitting...."
    except:
        print "\n" + warn + "Please report this error to " + __maintainer__ + " by email at: " + __email__
        raise
