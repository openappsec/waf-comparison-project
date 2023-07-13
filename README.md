# Web Application Firewall (WAF) Comparison Project

## Project Overview

This project repository contains testing datasets and tools to compare WAF efficacy in the two most important categories:

-	Security Coverage (True Positive Rate) - measures the WAF's ability to correctly identify and block malicious requests is crucial in today's threat landscape. It must preemptively block zero-day attacks as well as effectively tackle known attack techniques utilized by hackers
-	Precision (False Positive Rate) – measures the WAF's ability to correctly allow legitimate requests. Any hindrance to these valid requests could lead to significant business disruption and an increased workload for administrators.

This project aims to measure the efficacy of each WAF against a variety of legitimate and malicious HTTP requests, taken from real-world scenarios.


## Setup Instructions
Follow the steps below to set up and run the tool:


Download the necessary python requirements
```shell
pip install -r requirements.txt
```

### 1. Copy the Configuration Template
Copy the configuration template file by running the following command in the project's root directory:

```shell
cp config_template.py config.py
```
This command creates a copy of the config_template.py file and renames it to config.py.

### 2. Configure the Tool
Once your WAF environments are properly set up, it's time to configure the testing tool.

Open the config.py file in a text editor. Here, you'll find placeholders for WAF names and their corresponding URLs. Replace these with your specific details.

Once you've input all necessary data, save and close the config.py file. Your tool is now customized for your WAF systems and ready for testing.

### 3. Run the Tool
Execute the main runner file by running the following command:

   ```shell
   python3 runner.py 
   ```
This command starts the tool and executes the desired functionality.

### Running the Tool in a Linux Environment (Using tmux)
If you are running the script in a Linux environment, you can use tmux to keep the tool running even after detaching from the console.

Follow the steps below:

Enter the tmux terminal by running the command:

 ```shell
 tmux
 ```
Run the tool within the tmux session:

 ```shell
python3 runner.py 
```
To detach from the tmux console, press and hold Ctrl + b, release the keys, and then type d.

 ```
CTRL+b d
```
This detaches your current tmux session, leaving the tool running in the background.

To re-enter the tmux terminal again, use the following command:

```shell
tmux ls
```
Select the relevant terminal number from the list and run:

```shell
tmux attach-session -t <TERMINAL_NUMBER>
```
This command attaches you back to the tmux session where the tool is running.


## Methodology

Each WAF solution is tested against two data sets: legitimate and malicious. We then used a formula described below in detail to produce a single balanced score.

### Legitimate Data Set

The Legitimate Requests Dataset is carefully designed to test WAF behaviors in real-world scenarios. To attain this, it includes 973,964 different HTTP requests from 185 real-web sites in 12 categories. Each dataset was recorded by browsing to real-world web sites and conducting various operations in the site (for example, sign-up, selecting products and placing in a cart, etc) ensuring the presence of 100% legitimate requests.

The dataset can be found in the folder Data/Legitimate

### Malicious Data Set

The Malicious Requests Dataset includes 73,924 malicious payloads from a broad spectrum of commonly experienced attack vectors:
- SQL Injection-
- Cross-Site Scripting (XSS)
- XML External Entity (XXE)
- Path Traversal
- Command Execution
- Log4Shell
- Shellshock

The malicious payloads were sourced from the WAF Payload Collection GitHub page that was assembled by mgm security partners GmbH from Germany. This repository serves as a valuable resource, providing payloads specifically created for testing Web Application Firewall rules. 

The dataset is available <here>

## Tooling

To trigger the data sets through the different devices under tests, we developed a simple test tool in Python. The test tool is designed to ingest data sets as input and send each request to the various WAFs being tested. It reads the data files from the data sets and uses the requests module in a multi-threaded manner to send the data to each WAF. 

During the initial phase, the tool conducts a dual-layer health check for each WAF. This process first validates connectivity to each WAF, ensuring system communication. It then checks that each WAF is set to prevention mode, confirming its ability to actively block malicious requests.

The responses from each request sent by the test tool to the WAFs were systematically logged in a dedicated database for further analysis. The database we used is an AWS RDS instance running PostgreSQL (database is not included in this repo). You can configure it to work with any SQL database of their preference by adjusting the settings in the config.py file. 


## Running the Tests
The main file for running the tests is `runner.py`. This script will send the HTTP requests, log the responses, and calculate the performance metrics for each WAF.

**Note:** You may need to adjust the settings in the `config.py` file to suit your specific testing environment.

## License
The Legitimate Requests Datasetand the Tooling are available under Apache 2.0 license.
The Malicous Requests Dataset is a collection of datasets assembeled by MGM with different copyrights, mostly under MIT.

## Data Availability
The data sets used for this project are available via GitHub and will be updated annually.

## Related Resources
For an in-depth discussion and analysis of the results, see our [WAF Comparison Blog Post](link-to-be-added).

[MGM WAF Payload Collection](https://github.com/mgm-sp/WAF-Payload-Collection)


## Contact
For any questions or concerns, please open an issue in this GitHub repository.
