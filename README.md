# Twitter.ApiCaller  
NET Framework (*project targets 4.8*) library used to interact with Twitter API v2 and v1.1.  
  
## Quick start - scraping demonstration  
1. Load the library into **Windows PowerShell**.  
2. Initialize the utility by entering your **client key** and **client secret** as the first and second arguments in the constructor.  
3. Authenticate *(credential prompt is not visible in the demonstration below)*.  
4. Populate a user object by using the instance method **GetUser(**[string]"username",[bool]$True**)**. The boolean indicates whether to create a download folder ($true to create a folder).  
5. Instance method **RequestTimeLineMedia** calls the endpoint **api.twitter.com/2/timeline/media**  
6. Instance method **GetMediaUriFromTweetObject(**$utils.timeLineMediaTweets[0]**)** will output any of the direct media urls for pictures or videos hosted on Twitter.  
  
<img src="https://raw.githubusercontent.com/nstevens1040/Twitter.ApiCaller/master/.ignore/render1623916840633.gif" width=800 height=436>  
  
