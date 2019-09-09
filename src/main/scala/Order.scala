import io.gatling.core.Predef._
import io.gatling.http.Predef._
import com.tr.nest.crypto._
import org.bouncycastle.util.encoders._
import org.json.simple._;

object Order {
  
  private val csvFeeder = csv("Sample.csv").circular;

  private val reqGetInitialKey = exec(http("GetInitialKey")
    .post("/GetInitialKey")
    //.body(StringBody(userString))
    .check(bodyString.saveAs("BODY"))
    .check(jsonPath("$..publicKey").exists.saveAs("pubkey"))
    .check(
      status is 200)
  ).pause(1)
    .exec(sessionFunction = session => {
      val response = session("BODY").as[String]
      println(s"Response body: \n$response")
      //val key: String = session("pubkey").as[String]
      val serverPublicKey = new String(java.util.Base64.getDecoder.decode(session("pubkey").as[String]))
      val crypt = new CryptoRSA();
      val keyPair: NestKeyPair = crypt.generateNestKeyPair(512);
      val public = crypt.getPublicKeyFromPemData(serverPublicKey);
      val encryptedClientPublicKey: String = crypt.encrypt(keyPair.getPemPublicKey(), public, 2048);
      val md: java.security.MessageDigest = java.security.MessageDigest.getInstance("SHA-256");
      val digest: Array[Byte] = md.digest(serverPublicKey.getBytes());
      val hex: String = Hex.toHexString(digest);
      val jData: String = "jData="+java.net.URLEncoder.encode(encryptedClientPublicKey,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
      session.set("jData",jData).set("privateKey", keyPair.getPemPrivateKey())
    })

  private val reqGetPreAuthenticationKey = exec(http("GetPreAuthenticationKey")
    .post("/GetPreAuthenticationKey")
    .header("Content-Type", "application/x-www-form-urlencoded")
    .body(StringBody("${jData}"))
    .check(bodyString.saveAs("preAuthBody"))
    .check(jsonPath("$..publicKey3").exists.saveAs("serverkey3"))
    .check(
      status is 200)
  ).pause(1)
    .exec(session => {
      val response = session("preAuthBody").as[String];
      println(s"Response body: \n$response")
      val key3 = session("serverkey3").as[String]
      val uid = session("uid").as[String];
      val privateKey = session("privateKey").as[String];
      val crypt = new CryptoRSA();
      val keyPair: NestKeyPair = crypt.generateNestKeyPair(privateKey);
      val pubKey3 = crypt.decrypt(key3,keyPair.getPrivateKey());
      val md: java.security.MessageDigest = java.security.MessageDigest.getInstance("SHA-256");
      val digest: Array[Byte] = md.digest(pubKey3.getBytes());
      val hex: String = Hex.toHexString(digest);
      val sendJsonObject = "{\"uid\":\""+uid+"\"}";
      val key = crypt.getPublicKeyFromPemData(pubKey3);
      val encryptedSendObject = crypt.encrypt(sendJsonObject,key,2048);
      val jData: String = "jData="+java.net.URLEncoder.encode(encryptedSendObject,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
      session.set("jDataLogin",jData).set("serverPublicKey3", pubKey3).set("pubKey3Hash", hex)
    })

  private val reqLogin2FA = exec(http("Login2FA")
    .post("/Login2FA")
    .header("Content-Type", "application/x-www-form-urlencoded")
    .body(StringBody("${jDataLogin}"))
    .check(bodyString.saveAs("login2FABody"))
    .check(
      status is 200)
  ).pause(1)
    .exec(session => {
      val response = session("login2FABody").as[String];
      println(s"Response body: \n$response")
      val crypt = new CryptoRSA();
      val uid = session("uid").as[String];
      val password = session("password").as[String];
      val md: java.security.MessageDigest = java.security.MessageDigest.getInstance("SHA-256");
      var digest: Array[Byte] = md.digest(password.getBytes());
      for( w <- 1 to 999) {
        digest = md.digest(digest);
      }
      val passwordHash = Hex.toHexString(digest);
      println(s"passwordHash body: \n$passwordHash")
      val jsonObject = "{\"uid\":\""+uid+"\",\"pwd\":\""+passwordHash+"\",\"Imei\":\"123456789\",\"apk\":\"0.0.0.0\",\"ftl\":\"N\",\"Source\":\"MOB\"}"
      val hex = session("pubKey3Hash").as[String];
      val pubKey3 = session("serverPublicKey3").as[String];
      val key = crypt.getPublicKeyFromPemData(pubKey3);
      val encryptedSendObject = crypt.encrypt(jsonObject,key,2048);
      val jData: String = "jData="+java.net.URLEncoder.encode(encryptedSendObject,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
      session.set("jDataPwd",jData)
    })

  private val reqValidPwd = exec(http("ValidPwd")
    .post("/ValidPwd")
    .header("Content-Type", "application/x-www-form-urlencoded")
    .body(StringBody("${jDataPwd}"))
    .check(bodyString.saveAs("ValidPwdBody"))
    .check(jsonPath("$..scount").exists.saveAs("scount"))
    .check(jsonPath("$..sIndex").exists.saveAs("sIndex"))
    .check(
      status is 200)
  ).pause(1)
    .exec(session => {
      val response = session("ValidPwdBody").as[String];
      println(s"Response body: \n$response")
      val crypt = new CryptoRSA();
      val uid = session("uid").as[String];
      val scount = session("scount").as[String]
      val sIndex = session("sIndex").as[String].replaceAll("\\|","-");
      val answer1 = session("answer1").as[String];
      val answer2 = session("answer1").as[String];
      val jsonObject = "{\"uid\":\""+uid+"\",\"Count\":\""+scount+"\",\"as\":\""+answer1+"-"+answer2+"\",\"is\":\""+sIndex+"\"}";
      val hex = session("pubKey3Hash").as[String];
      val pubKey3 = session("serverPublicKey3").as[String];
      val key = crypt.getPublicKeyFromPemData(pubKey3);
      val encryptedSendObject = crypt.encrypt(jsonObject,key,2048);
      val jData: String = "jData="+java.net.URLEncoder.encode(encryptedSendObject,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
      session.set("jDataPwd",jData)
    })

  private val reqValidAns = exec(http("ValidAns")
    .post("/ValidAns")
    .header("Content-Type", "application/x-www-form-urlencoded")
    .body(StringBody("${jDataPwd}"))
    .check(bodyString.saveAs("ValidAnsBody"))
    .check(jsonPath("$..jEncResp").exists.saveAs("jEncResp"))
    .check(
      status is 200)
  ).pause(1)
    .exec(session => {
      val response = session("ValidAnsBody").as[String];
      println(s"Response body: \n$response")
      val jEncResp = session("jEncResp").as[String]
      val crypt = new CryptoRSA();
      val privateKey = session("privateKey").as[String];
      val keyPair: NestKeyPair = crypt.generateNestKeyPair(privateKey);
      val decryptResponse = crypt.decrypt(jEncResp,keyPair.getPrivateKey());
      println(s"decryptResponse body: \n$decryptResponse")
      // val jObj = new JSONObject()
      // val jObj:JSONObject = (JSONObject)JSONValue.parse(decryptResponse);
      val obj = JSONValue.parse(decryptResponse);
      val jobj = obj.asInstanceOf[JSONObject];
      val pubKey4 = jobj.get("sUserToken");
      val sUserSessionId = jobj.get("UserSessionID");
      val md: java.security.MessageDigest = java.security.MessageDigest.getInstance("SHA-256");
      val digest: Array[Byte] = md.digest(pubKey4.asInstanceOf[String].getBytes());
      val hex: String = Hex.toHexString(digest);
      val uid = session("uid").as[String];
      val jsonObject = "{\"uid\":\""+uid+"\",\"imei\":\"123456789\"}";
      val key = crypt.getPublicKeyFromPemData(pubKey4.asInstanceOf[String]);
      val encryptedSendObject = crypt.encrypt(jsonObject,key,2048);
      val jData: String = "jData="+java.net.URLEncoder.encode(encryptedSendObject,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
      session.set("jDataAns",jData).set("usersessionid", sUserSessionId).set("serverPublicKey4", hex).set("pubKey4Hash", pubKey4)
    })

  private val reqDefaultLogin = exec(http("DefaultLogin")
    .post("/DefaultLogin")
    .header("Content-Type", "application/x-www-form-urlencoded")
    .body(StringBody("${jDataAns}"))
    .check(bodyString.saveAs("DefaultLoginBody"))
    .check(
      status is 200)
  ).pause(1)
    .exec(session => {
      val response = session("DefaultLoginBody").as[String];
      println(s"Response body: \n$response")
      session.set("LOGIN","LOGGEDIN")
    })

    private val reqMWList =
      exec(session => {
        val crypt = new CryptoRSA();
        val pubKey4 = session("pubKey4Hash").as[String];
        val hex = session("serverPublicKey4").as[String];
        val uid = session("uid").as[String];
        val jsonObject = "{\"uid\":\""+uid+"\"}";
        val key = crypt.getPublicKeyFromPemData(pubKey4);
        val encryptedSendObject = crypt.encrypt(jsonObject,key,2048);
        val jData: String = "jData="+java.net.URLEncoder.encode(encryptedSendObject,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
        session.set("jDataMW",jData)
      }).
        exec(http("MWList")
          .post("/MWList")
          .header("Content-Type", "application/x-www-form-urlencoded")
          .body(StringBody("${jDataMW}"))
          .check(bodyString.saveAs("MWBody"))
          .check(jsonPath("$..values[0]").exists.saveAs("values"))
          .check(
            status is 200)
        ).pause(1)
        .exec(session => {
          val response = session("MWBody").as[String];
          println(s"Response body: \n$response")
          session.set("LOGIN","LOGGEDIN")
        })

    private val reqMarketWatch =
      exec(session => {
        val crypt = new CryptoRSA();
        val pubKey4 = session("pubKey4Hash").as[String];
        val hex = session("serverPublicKey4").as[String];
        val names = session("values").as[String];
        val uid = session("uid").as[String];
        val jsonObject = "{\"uid\":\"" + uid + "\",\"MWname\":\"" + names + "\"}"
        val key = crypt.getPublicKeyFromPemData(pubKey4);
        val encryptedSendObject = crypt.encrypt(jsonObject,key,2048);
        val jData: String = "jData="+java.net.URLEncoder.encode(encryptedSendObject,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
        session.set("jDataMarketWatch",jData)
      }).
        exec(http("MarketWatch")
          .post("/MarketWatch")
          .header("Content-Type", "application/x-www-form-urlencoded")
          .body(StringBody("${jDataMarketWatch}"))
          .check(bodyString.saveAs("MarketWatchBody"))
          .check(
            status is 200)
        ).pause(1)
        .exec(session => {
          val response = session("MarketWatchBody").as[String];
          println(s"Response body: \n$response")
          session
        })

    private val reqGetLotWeight =
      exec(session => {
        val crypt = new CryptoRSA();
        val pubKey4 = session("pubKey4Hash").as[String];
        val hex = session("serverPublicKey4").as[String];
        val uid = session("uid").as[String];
        val jsonObject = "{\"uid\":\""+uid+"\"}";
        val key = crypt.getPublicKeyFromPemData(pubKey4);
        val encryptedSendObject = crypt.encrypt(jsonObject,key,2048);
        val jData: String = "jData="+java.net.URLEncoder.encode(encryptedSendObject,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
        session.set("jDataGetLotWeight",jData)
      }).
        exec(http("GetLotWeight")
          .post("/GetLotWeight")
          .header("Content-Type", "application/x-www-form-urlencoded")
          .body(StringBody("${jDataGetLotWeight}"))
          .check(bodyString.saveAs("GetLotWeightBody"))
          .check(
            status is 200)
        ).pause(1)
        .exec(session => {
          val response = session("GetLotWeightBody").as[String];
          println(s"Response body: \n$response")
          session
        })

    private val reqLoadRetentionType =
      exec(session => {
        val crypt = new CryptoRSA();
        val pubKey4 = session("pubKey4Hash").as[String];
        val hex = session("serverPublicKey4").as[String];
        val uid = session("uid").as[String];
        val jsonObject = "{\"Exchange\":\"NSE\"}";
        val key = crypt.getPublicKeyFromPemData(pubKey4);
        val encryptedSendObject = crypt.encrypt(jsonObject,key,2048);
        val jData: String = "jData="+java.net.URLEncoder.encode(encryptedSendObject,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
        session.set("jDataLoadRetentionType",jData)
      }).
        exec(http("LoadRetentionType")
          .post("/LoadRetentionType")
          .header("Content-Type", "application/x-www-form-urlencoded")
          .body(StringBody("${jDataLoadRetentionType}"))
          .check(bodyString.saveAs("LoadRetentionTypeBody"))
          .check(
            status is 200)
        ).pause(1)
        .exec(session => {
          val response = session("LoadRetentionTypeBody").as[String];
          println(s"Response body: \n$response")
          session
        })

    private val reqConfirmMsg =
      exec(session => {
        val crypt = new CryptoRSA();
        val pubKey4 = session("pubKey4Hash").as[String];
        val hex = session("serverPublicKey4").as[String];
        val uid = session("uid").as[String];
        val jsonObject = "{\"uid\":\""+uid+"\",\"Exchange\":\"NSE\",\"TradSym\":\"ACC-EQ\"}";
        val key = crypt.getPublicKeyFromPemData(pubKey4);
        val encryptedSendObject = crypt.encrypt(jsonObject,key,2048);
        val jData: String = "jData="+java.net.URLEncoder.encode(encryptedSendObject,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
        session.set("jDataConfirmMsg",jData)
      }).
        exec(http("ConfirmMsg")
          .post("/Orders/ConfirmMsg")
          .header("Content-Type", "application/x-www-form-urlencoded")
          .body(StringBody("${jDataConfirmMsg}"))
          .check(bodyString.saveAs("ConfirmMsgBody"))
          .check(
            status is 200)
        ).pause(1)
        .exec(session => {
          val response = session("ConfirmMsgBody").as[String];
          println(s"Response body: \n$response")
          session
        })

    private val reqOrderBook =
      exec(session => {
        val crypt = new CryptoRSA();
        val pubKey4 = session("pubKey4Hash").as[String];
        val hex = session("serverPublicKey4").as[String];
        val uid = session("uid").as[String];
        val jsonObject = "{\"uid\": \""+uid+"\", \"s_prdt_ali\": \"BO:BO||CNC:CNC||CO:CO||MIS:MIS||NRML:NRML\"}";
        val key = crypt.getPublicKeyFromPemData(pubKey4);
        val encryptedSendObject = crypt.encrypt(jsonObject,key,2048);
        val jData: String = "jData="+java.net.URLEncoder.encode(encryptedSendObject,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
        session.set("jDataOrderBook",jData)
      }).
        exec(http("OrderBook")
          .post("/OrderBook")
          .header("Content-Type", "application/x-www-form-urlencoded")
          .body(StringBody("${jDataOrderBook}"))
          .check(bodyString.saveAs("OrderBookBody"))
          .check(
            status is 200)
        ).pause(1)
        .exec(session => {
          val response = session("OrderBookBody").as[String];
          println(s"Response body: \n$response")
          session
        })

    private val reqTradeBook =
      exec(session => {
        val crypt = new CryptoRSA();
        val pubKey4 = session("pubKey4Hash").as[String];
        val hex = session("serverPublicKey4").as[String];
        val uid = session("uid").as[String];
        val jsonObject = "{\"uid\": \""+uid+"\", \"s_prdt_ali\": \"BO:BO||CNC:CNC||CO:CO||MIS:MIS||NRML:NRML\"}";
        val key = crypt.getPublicKeyFromPemData(pubKey4);
        val encryptedSendObject = crypt.encrypt(jsonObject,key,2048);
        val jData: String = "jData="+java.net.URLEncoder.encode(encryptedSendObject,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
        session.set("jDataTradeBook",jData)
      }).
        exec(http("TradeBook")
          .post("/TradeBook")
          .header("Content-Type", "application/x-www-form-urlencoded")
          .body(StringBody("${jDataTradeBook}"))
          .check(bodyString.saveAs("TradeBookBody"))
          .check(
            status is 200)
        ).pause(1)
        .exec(session => {
          val response = session("TradeBookBody").as[String];
          println(s"Response body: \n$response")
          session
        })

    private val reqPositionBook =
      exec(session => {
        val crypt = new CryptoRSA();
        val pubKey4 = session("pubKey4Hash").as[String];
        val hex = session("serverPublicKey4").as[String];
        val uid = session("uid").as[String];
        val jsonObject = "{\"uid\": \""+uid+"\", \"actid\": \""+uid+"\", \"s_prdt_ali\": \"BO:BO||CNC:CNC||CO:CO||MIS:MIS||NRML:NRML\", \"type\": \"NET\"}";
        val key = crypt.getPublicKeyFromPemData(pubKey4);
        val encryptedSendObject = crypt.encrypt(jsonObject,key,2048);
        val jData: String = "jData="+java.net.URLEncoder.encode(encryptedSendObject,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
        session.set("jDataPositionBook",jData)
      }).
        exec(http("PositionBook")
          .post("/PositionBook")
          .header("Content-Type", "application/x-www-form-urlencoded")
          .body(StringBody("${jDataPositionBook}"))
          .check(bodyString.saveAs("PositionBookBody"))
          .check(
            status is 200)
        ).pause(1)
        .exec(session => {
          val response = session("PositionBookBody").as[String];
          println(s"Response body: \n$response")
          session
        })

    private val reqLimits =
      exec(session => {
        val crypt = new CryptoRSA();
        val pubKey4 = session("pubKey4Hash").as[String];
        val hex = session("serverPublicKey4").as[String];
        val uid = session("uid").as[String];
        val jsonObject = "{\"uid\": \""+uid+"\", \"actid\": \""+uid+"\", \"segment\":\"ALL\"}";
        val key = crypt.getPublicKeyFromPemData(pubKey4);
        val encryptedSendObject = crypt.encrypt(jsonObject,key,2048);
        val jData: String = "jData="+java.net.URLEncoder.encode(encryptedSendObject,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
        session.set("jDataLimits",jData)
      }).
        exec(http("Limits")
          .post("/Limits")
          .header("Content-Type", "application/x-www-form-urlencoded")
          .body(StringBody("${jDataLimits}"))
          .check(bodyString.saveAs("LimitsBody"))
          .check(
            status is 200)
        ).pause(1)
        .exec(session => {
          val response = session("LimitsBody").as[String];
          println(s"Response body: \n$response")
          session
        }).pause(1)

    private val reqLogout =
      exec(session => {
        val crypt = new CryptoRSA();
        val pubKey4 = session("pubKey4Hash").as[String];
        val hex = session("serverPublicKey4").as[String];
        val uid = session("uid").as[String];
        val jsonObject = "{\"uid\": \""+uid+"\"}";
        val key = crypt.getPublicKeyFromPemData(pubKey4);
        val encryptedSendObject = crypt.encrypt(jsonObject,key,2048);
        val jData: String = "jData="+java.net.URLEncoder.encode(encryptedSendObject,"UTF-8")+"&jKey="+java.net.URLEncoder.encode(hex,"UTF-8");
        session.set("jDataLogout",jData)
      }).
        exec(http("Logout")
          .post("/Logout")
          .header("Content-Type", "application/x-www-form-urlencoded")
          .body(StringBody("${jDataLogout}"))
          .check(bodyString.saveAs("LogoutBody"))
          .check(
            status is 200)
        ).pause(1)
        .exec(session => {
          val response = session("LogoutBody").as[String];
          println(s"Response body: \n$response")
          session
        })



    val scnOrder = Constants.createScenario("PlaceOrder", csvFeeder,
      reqGetInitialKey, reqGetPreAuthenticationKey, reqLogin2FA, reqValidPwd, reqValidAns, reqDefaultLogin
        .repeat(6){
          exec(reqMWList).
            exec(reqMarketWatch).
            exec(reqGetLotWeight).
            exec(reqLoadRetentionType).
            exec(reqConfirmMsg).
            exec(reqOrderBook).
            exec(reqTradeBook).
            exec(reqPositionBook).
            exec(reqLimits)
        }
        .doIfEquals("${LOGIN}", "LOGGEDIN") {
          reqLogout
        })


    //    val scnFeed = Constants.createScenario("SockerFeed", csvFeeder,
    //        reqGetInitialKey, reqGetPreAuthenticationKey, reqLogin2FA, reqValidAns,reqDefaultLogin)
  }