__author__ = 'Russel Van Tuyl'
__maintainer__ = "Russel Van Tuyl"
__email__ = "Russel.VanTuyl@gmail.com"
__version__ = "1.0"

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
        rs = connection.execute("""SELECT session_id, checkin_time FROM agents;""")

        for r in rs:
            agents[r[0]] = {'checkin_time':r[1], 'session_id':r[0]}

        connection.close()
    except sqlite3.OperationalError:
        print warn + "Error connecting to the database at %s" % dbPath

    return agents


def msf_rpc_request(payload):
    """Make HTTP POST Request to MSF RPC Interface"""

    url = "http://" + msfRpcHost + ":" + msfRpcPort + "/api/1.1"
    headers = {'content-type': 'binary/message-pack'}
    try:
        response = requests.post(url, data=payload, headers=headers, verify=False)
        return response
    except requests.exceptions.ConnectionError:
        print warn + "SlackShellBot will continue without Metasploit because it was unable to communicate with the RPC"\
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
                print "\tMSF RPC Server Response: %s" % msf_rpc_message
                if 'error' in msf_rpc_message.keys():
                    print debug + "MSF RPC Error: %s" % msf_rpc_message['error_message']
            else:
                print "\tHTTP Server Response: %s" % response.content
        if response.status_code == 200:
            result = msgpack.unpackb(response.content, use_list=False)
            if 'error' in result.keys():
                print warn + "MSF RPC Error: %s" % result['error_message']
                print warn + "Quitting"
                sys.exit()
            elif 'token' in result.keys():
                msfRpcToken = result['token']


def msf_rpc_get_core_version():
    """Get Metasploit instance version information"""

    payload = msgpack.packb(["core.version", msf_rpc_token])
    response = msf_rpc_request(payload)
    result = msgpack.unpackb(response.content, use_list=False)
    return result


def msf_rpc_get_session_list():
    """Get a list of Meterpreter sessions"""

    payload = msgpack.packb(["session.list", msfRpcToken])
    response = msf_rpc_request(payload)
    result = msgpack.unpackb(response.content, use_list=False)

    if response.status_code == 200:
        return result
    else:
        return None


def send_new_agent_message(agentType, payload):
    """Send New Agent Message to Slack"""

    if DEBUG:
        print debug + "New agent message agent: %s, payload: %s" % (agentType, payload)

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
        print response.text
        print response.status_code
    if response.status_code == 200:
        print info + "New %s Agent Check in Successfully Posted to Slack" % agentType
        print "\t" + note + "%s" % payload.replace("\n", ", ")
    else:
        print warn + "Message not posted to Slack. HTTP Status Code: %s" % response.status_code


def parse_config(configFile):
    """Parse the SlackShellBot configuration file and update global variables"""

    global sleepTime
    global slackHook
    global botName
    global channel
    global empireDb
    global msfRpcHost
    global msfRpcPort
    global msfRpcUser
    global msfRpcPass

    if VERBOSE:
        print note + "Parsing config file at %s" % configFile

    c = ConfigParser.ConfigParser()
    c.read(configFile)

    if c.has_section("slack"):
        if c.has_option("slack", "slackHook"):
            slackHook = c.get("slack", "slackHook")
        else:
            print warn + "Configuration file missing 'slackHook' parameter in 'slack' section"
            os._exit(1)
        if c.has_option("slack", "botName"):
            botName = c.get("slack", "botName")
        else:
            print warn + "Configuration file missing 'botName' parameter in 'slack' section"
            os._exit(1)
        if c.has_option("slack", "channel"):
            channel = c.get("slack", "channel")
        else:
            print warn + "Configuration file missing 'channel' parameter in 'slack' section"
            os._exit(1)
    else:
        print warn + "Missing 'slack' section in configuration file"
        os._exit(1)

    # This section can be missing, will use global variables instead
    if c.has_section("slackShellBot"):
        if c.has_option("slackShellBot", "sleepTime"):
            sleepTime = c.getint("slackShellBot", "sleepTime")

    if c.has_section("empire"):
        if c.has_option("empire", "db"):
            e = c.get("empire", "db")
            if os.path.isfile(os.path.join(ssb_root, e)):
                empireDb = os.path.join(ssb_root, e)
            else:
                print warn + "SlackShellBot will continue without Empire because database was not found at %s" \
                             % os.path.join(ssb_root, e)
        else:
            print warn + "SlackShellBot will continue without Empire because database path not provided."
    else:
        print warn + "SlackShellBot will continue without Empire because configuration was not provided."

    if c.has_section("msf"):
        if c.has_option("msf", "msfRpcHost"):
            msfRpcHost = c.get("msf", "msfRpcHost")
        else:
            print warn + "SlackShellBot will continue without Metasploit Framework because the " \
                         "host was not provided"
        if c.has_option("msf", "msfRpcPort"):
            msfRpcPort = c.get("msf", "msfRpcPort")
        else:
            print warn + "SlackShellBot will continue without Metasploit Framework because the " \
                         "port was not provided"
        if c.has_option("msf", "msfRpcUser"):
            msfRpcUser = c.get("msf", "msfRpcUser")
        else:
            print warn + "SlackShellBot will continue without Metasploit Framework because the " \
                         "user was not provided"
        if c.has_option("msf", "msfRpcPass"):
            msfRpcPass = c.get("msf", "msfRpcPass")
        else:
            print warn + "SlackShellBot will continue without Metasploit Framework because the " \
                         "password was not provided"
    else:
        print warn + "SlackShellBot will continue without Metasploit because configuration was not provided."

    msf_rpc_get_temp_auth_token()


def check_empire_agents(db):
    """Check for new Empire agents"""

    global knownAgents

    agents = db_query(db)

    if DEBUG:
        print agents
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
                send_new_agent_message("Empire", msg)


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
                    send_new_agent_message("Meterpreter", msg)


if __name__ == '__main__':

    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('--debug', action='store_true', default=False, help="Enable debug output to console")
        parser.add_argument('-v', action='store_true', default=False, help="Enable verbose output to console")
        args = parser.parse_args()
        VERBOSE = args.v
        DEBUG = args.debug

        conf = os.path.join(ssb_root, "ssb.conf")
        parse_config(conf)

        if (empireDb is not None) or (msfRpcToken is not None):
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
            os._exit(1)

    except KeyboardInterrupt:
        print "\n" + warn + "User Interrupt! Quitting...."
    except:
        print "\n" + warn + "Please report this error to " + __maintainer__ + " by email at: " + __email__
        raise