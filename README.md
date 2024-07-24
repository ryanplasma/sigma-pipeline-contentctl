# sigma-pipeline-contentctl
This is an experimental [pySigma](https://github.com/SigmaHQ/pySigma)/[sigma-cli](https://github.com/SigmaHQ/sigma-cli) pipeline file using [sigma query postprocessing](https://blog.sigmahq.io/introducing-query-post-processing-and-output-finalization-to-processing-pipelines-4bfe74087ac1) to convert a sigma rule into Splunk's [contentctl](https://github.com/splunk/contentctl) yaml format.

## How To Use
Requirements:
* pySigma >= 0.10

This pipeline file can be integrated into your existing Sigma to Splunk conversion process. For example heres how it could be used with sigma-cli:

`sigma convert -t splunk -p splunk_cim -p path/to/your/pipelines/splunk_contentctl_pipeline.yml -f data_model sigma/rules/windows/process_creation/proc_creation_win_susp_recon.yml`

which will output this:

```
Parsing Sigma rules  [####################################]  100%
name: Recon Information for Export with Command Prompt
id: aa2efee7-34dd-446e-8a37-40790a66efd7
version: 1
date: 2021-07-30
author: frack113
data_sources:
- UPDATE
type: UPDATE
status: validation
description: Once established within a system or network, an adversary may use automated techniques for collecting internal data.
kind: UPDATE
search: '| tstats summariesonly=false allow_old_summaries=true fillnull_value="null" count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_path IN ("*\\tree.com", "*\\WMIC.exe", "*\\doskey.exe", "*\\sc.exe") OR Processes.original_file_name IN ("wmic.exe", "DOSKEY.EXE", "sc.exe") Processes.parent_process IN ("* > %TEMP%\\*", "* > %TMP%\\*") by Processes.process Processes.dest Processes.process_current_directory Processes.process_path Processes.process_integrity_level Processes.original_file_name Processes.parent_process Processes.parent_process_path Processes.parent_process_guid Processes.parent_process_id Processes.process_guid Processes.process_id Processes.user | `drop_dm_object_name(Processes)` | convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) | convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime) '
how_to_implement: UPDATE_HOW_TO_IMPLEMENT
known_false_positives:
- Unknown
references:
- https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1119/T1119.md
tags:
  analytic_story:
  - UPDATE_STORY_NAME
  asset_type: UPDATE asset_type
  confidence: UPDATE value between 1-100
  impact: UPDATE value between 1-100
  message: UPDATE message
  mitre_attack_id:
  - UPDATE
  observable:
  - name: UPDATE
    type: UPDATE
    role:
    - UPDATE
  product:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  required_fields:
  - UPDATE
  risk_score: UPDATE (impact * confidence)/100
  security_domain: UPDATE
  cve:
  - UPDATE WITH CVE(S) IF APPLICABLE
tests:
- name: True Positive Test
  attack_data:
  - data: https://github.com/splunk/contentctl/wiki
    sourcetype: UPDATE SOURCETYPE
    source: UPDATE SOURCE
```

From here you can update the necessary fields and add it to your contentctl powered repo. 

## FAQ
* Why a yaml file and not an addition to the splunk plugin?
    *  This was easier and more flexible but in the future I could see it being an additional output format 

* Why do I need to update so many fields?
  * I wanted to keep this as generic as possible so that it would fit into any workflow. 

