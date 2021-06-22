# Twitter.ApiCaller  
.NET Framework (*project targets 4.8*) library used to interact with Twitter API v2 and v1.1.  

## Quick Start  
  
Use these batch commands to clone and compile.  
  
```bat
for /f "usebackq tokens=4 delims= " %i in (`wmic product get description ^| findstr /C:".NET Framework 4.8 Targeting Pack"`) do @SET DOTNETVERSION=%i
@IF %DOTNETVERSION% NEQ 4.8 @powershell -noprofile -ep remotesigned -c [System.Net.WebClient]::New().DownloadFile('https://download.visualstudio.microsoft.com/download/pr/014120d7-d689-4305-befd-3cb711108212/0307177e14752e359fde5423ab583e43/ndp48-devpack-enu.exe',$env:USERPROFILE + '\Downloads\ndp48-devpack-enu.exe') && @%USERPROFILE%\Downloads\ndp48-devpack-enu.exe /install /quiet /norestart && @powershell -noprofile -ep remotesigned -c while(Get-Process -Name ndp48-devpack-enu -ea 0){}
@IF EXIST "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe" @for /f "usebackq tokens=1* delims=: " %i in (`@"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"  -latest -requires Microsoft.Component.MSBuild`) do @if /i "%i"=="installationPath" set MSBUILD="%j\MSBuild\Current\Bin\MSBuild.exe" ELSE (
    @powershell -noprofile -ep remotesigned -c ([System.Net.WebClient]::New()).DownloadFile('https://download.visualstudio.microsoft.com/download/pr/2d4f424c-910d-4198-80de-aa829c85ae6a/8a2d8fc2b4e671de2dd45554558c0ad6949bd2fdbfefc284e6e147cf90f4b42d/vs_BuildTools.exe',$ENV:USERPROFILE + '\Downloads\vs_BuildTools.exe') && %USERPROFILE%\Downloads\vs_BuildTools.exe --add Microsoft.VisualStudio.Workload.MSBuildTools --quiet && @powershell -noprofile -ep remotesigned -c while(Get-Process -Name 'vs_BuildTools' -ea 0){} && SET MSBUILD=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\MSBuild\Current\Bin\MSBuild.exe
SET PSCMD=while(!(test-path '%MSBUILD%' -ea 0)){}
@powershell -noprofile -ep remotesigned -c %PSCMD%
git clone https://github.com/nstevens1040/Twitter.ApiCaller.git && cd Twitter.ApiCaller && "%MSBUILD%"

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
  
