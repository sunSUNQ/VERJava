# README

> This work represents my first independently completed research project during my doctoral studies.
> As a result, the code may contain numerous bugs and issues.
> I have made every effort to minimize manual specifications and definitions, and have conducted script testing in an alternate environment.
> The refactored code is capable of reproducing the experimental data and conclusions presented in the research paper.



## Files and Folders
- diff_file: Location for storing patch files
- patch_info: Extracted patch features on a per-function basis after analysis
- source_code: Source code packages for various versions of the target project
- tomcat: Project checked out from git
- version_java_file: Pre-patch and post-patch files
- git_control_handle.py: For git-managed projects, input diff files and extract patch features on a per-function basis (patch_info)
- svn_control_handle.py: For svn-managed projects, input diff files and extract patch features on a per-function basis (patch_info)
- new_range_analysis_source.py: Analyze CVE existing versions based on extracted patch_infos## 说明



## Running

### Step 1: Generate patch_info
The first parameter is the target project name, and the second parameter is the CVE ID

```cmd
$ python git_control_handler.py tomcat CVE-2008-1232
```

### Step 2: Analyze CVE existing versions
The first parameter is the target project name, and the second parameter is the CVE ID

```cmd
$ python new_range_analysis_source.py tomcat CVE-2008-1232
```



## Dependencies

Environment：window10 python 3.7.2

Requires installation of:

```python
from collections import OrderedDict
from unidiff import PatchSet
```

## Manual modification of local paths required

### git_control_handler.py (svn_control_handler.py)
- dir_path: Path where the project code package is located
- repo_name: Project name
- cve_id: Specify the CVE ID for analysis
- repo_path: For svn management, it's the svn project directory; for git management, it's the git project directory

### new_range_analysis_source.py
- repo_name: Project name
- cve_id: Specify the CVE ID for analysis
- DEBUG: Enable comments



## Issues
This method requires confirmation of the function name where the patch code is located in the patch file. 
The existing regex method cannot achieve 100% recognition accuracy, hence manual confirmation is needed (patch_func parameter in the patch_info file). 
When there are multiple functions with the same name in a file, it needs to be set to 'no'. 
When the patch fix is inside a class member function, it needs to be set to 'no'.



## Future
For future research and improvement of the tool, I have the following suggestions:

1. Evaluation across a broader range of languages and vulnerabilities: Currently, I have only discussed the capabilities on a subset of vulnerabilities in the Java language. There is potential for extended research, although this may require significant human effort for data annotation.

2. Further algorithmic refinement to enhance precision and recall: While VERJava achieves a 90% recognition capability, there are still many cases it cannot identify. Further classification, refinement, and generalization represent promising research directions.

3. Consideration of patch and vulnerability semantics: Our experimental dataset revealed that simple similarity analysis can yield good results. Due to project constraints and personal limitations, lightweight matching methods were chosen over more heavyweight algorithmic considerations such as semantics. Given the recent popularity of large language models, exploring the integration of semantic analysis represents a promising avenue for investigation.

4. Minor adjustments: Improving the accuracy of function name recognition and enhancing the tool's ability to identify tags in different software.
