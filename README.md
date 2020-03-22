# FortiSOAR Alert Simulator:
## Introduction:
A tool meant to be used during demos to simulate a SOAR environement by sending a series of alerts with a specific timing according to a template. this creates a scenario to illustrate targeted FortiSOAR capabilities.
it is meant to run on FortiSOAR to simulates an Asset network (Defined in the topology pptx) connected to the internet via FortiGate Firewall (FortiGate-Edge) and a set of alert sources including:
-FortiSIEM
-Qradar
-Others to come
The Environement requires a FortiGate to be used as a response enforcement point.

## Components:
-Main script: The main cli

-Modules Directory: Contain various functions libraries

-Templates Directory: Contains the available templates to be used during the demo, each template file represents a scenario. it is a list of dictionary objects.
### Templates:
The template must not contain a duplicate of the dynamic variable, if a source IP for example is used as srcIpAddr, 
so IncidentSrc should be empty. this is to maintain alert consitancy
Template file contains the static text as sent from the alert source device and a set of variables delimited with {{}}. all the variables
will be replaced with their dynamic value at runtime. when a list of alerts is present within the same template it's possible to have different variable values
by adding a digit at the end of the variable, example : {{TR_ASSET_IP}} is present in both alerts of the same template and we want its value to be different, 
we can write it as : {{TR_ASSET_IP}}1 in the first alert and {{TR_ASSET_IP}}2 in the second, so whatever value will be taken at runtime it will have 1 and 2 
at its end respectively 
