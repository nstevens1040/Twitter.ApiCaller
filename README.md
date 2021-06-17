# Twitter.ApiCaller  
.NET Framework (*project targets 4.8*) library used to interact with Twitter API v2 and v1.1.  

## Quick Start  
  
Use these batch commands to clone and compile.  
  
```bat
SET VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe
@for /f "usebackq tokens=1* delims=: " %i in (`@"%VSWHERE%"  -latest -requires Microsoft.Component.MSBuild`) do @if /i "%i"=="installationPath" set MSBUILD="%j\MSBuild\Current\Bin\MSBuild.exe"
git clone https://github.com/nstevens1040/Twitter.ApiCaller.git
cd Twitter.ApiCaller
%MSBUILD%
```  
*(If you end up copying the script above into a batch file as opposed to running the commands interactively, then make sure you replace each **%** with **%%**.)*  
  
## scraping demonstration  
1. Load the library into **Windows PowerShell**.  
2. Initialize the utility by entering your **client key** and **client secret** as the first and second arguments in the constructor.  
3. Authenticate *(credential prompt is not visible in the demonstration below)*.  
4. Populate a user object by using the instance method **GetUser(**[string]"username",[bool]$True). The boolean indicates whether to create a download folder (**$true** to create a folder).  
5. Instance method **RequestTimeLineMedia()** calls the endpoint **api.twitter.com/2/timeline/media**  
6. Instance method **GetMediaUriFromTweetObject(**$utils.timeLineMediaTweets[0]) will output any of the direct media urls for pictures or videos hosted on Twitter.  
  
<img src="https://raw.githubusercontent.com/nstevens1040/Twitter.ApiCaller/master/.ignore/render1623916840633.gif" width=800 height=436>  
  
