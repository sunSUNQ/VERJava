## 说明

diff_file：补丁文件存储位置

patch_info：分析后的以函数为单位提取的补丁特征

source_code：分析目标项目各个版本的源代码包

tomcat：git checkout 下来的项目

version_java_file：pre-patch and post-patch files

git_control_handle.py：对git管理的项目，输入diff文件，提取函数为单位的补丁特征（patch_info）

svn_control_handle.py：对svn管理的项目，输入diff文件，提取函数为单位的补丁特征（patch_info）

new_range_analysis_source.py：根据CVE提取到的patch_infos分析CVE存在版本。



第一步：生成patch_info

第一个参数为目标项目名称，第二个参数为CVE ID

```cmd
$ python git_control_handler.py tomcat CVE-2008-1232
```



第二步：分析cve存在版本

第一个参数为目标项目名称，第二个参数为CVE ID

```cmd
$ python new_range_analysis_source.py tomcat CVE-2008-1232
```



## 依赖

环境：window10 python 3.7.2

需下载安装：

```python
from collections import OrderedDict
from unidiff import PatchSet
```



## 需手动修改本地路径

#### git_control_handler.py（svn_control_handler.py）

dir_path：项目代码包所在路径

repo_name：项目名

cve_id：指定分析CVE ID

repo_path：svn管理中为svn的项目目录，git管理时为git项目目录



#### new_range_analysis_source.py

repo_name：项目名

cve_id：指定分析CVE ID

DEBUG：是否开启注释



## 问题

本方法需要确认补丁文件中补丁代码所在函数名，现有正则方法不能达到100%的识别准确率，因此需要人工二次确认。（patch_info文件中的patch_func参数）

当文件中存在多个同名函数时，需要设置为‘no’。

当补丁修复在类成员函数内，需要设置为‘no’。



svn与git文件路径都为为了分析函数名才存在的，若没有配置成功，则默认patch_func为‘no’。

