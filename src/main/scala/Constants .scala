//import io.gatling.core.Predef._
//import io.gatling.http._
import io.gatling.core.feeder._
import io.gatling.core.structure._
import io.gatling.core.Predef._
import io.gatling.core.check._
import io.gatling.http.Predef._
import com.tr.nest.crypto._
import org.bouncycastle.util.encoders._

object Constants  {
  
  val numberOfUsers: Int = System.getProperty("numberOfUsers").toInt;
    val duration = System.getProperty("durationMinutes").toInt;
    val pause = System.getProperty("pauseBetweenRequestsMs").toInt.toCoarsest;
    val responseTimeMs = 500;
    val responseSuccessPercentage = 99;
    private val url: String = System.getProperty("url");
    private val repeatTimes: Int = System.getProperty("numberOfRepetitions").toInt;
    private val successStatus: Int = 200;
    private val isDebug = System.getProperty("debug").toBoolean;
 
    val httpProtocol = http
        .baseUrl(url)
        .check(status.is(successStatus))
//        .extraInfoExtractor { extraInfo => List(getExtraInfo(extraInfo)) }
 
    def createScenario(name: String, feed: FeederBuilder, chains: ChainBuilder*): ScenarioBuilder = {
        if (Constants.repeatTimes > 0) {
            scenario(name).feed(feed).repeat(Constants.repeatTimes) {
                exec(chains).pause(Constants.pause)
            }
        } else {
            scenario(name).feed(feed).forever() {
                exec(chains).pause(Constants.pause)
            }
        }
    }
 
//    private def getExtraInfo(extraInfo: ExtraInfo): String = {
//        if (isDebug
//            || extraInfo.response.statusCode.get != successStatus
//            || extraInfo.status.eq(Status.apply("KO"))) {
//            ",URL:" + extraInfo.request.getUrl +
//                " Request: " + extraInfo.request.getStringData +
//                " Response: " + extraInfo.response.body.string
//        } else {
//            ""
//        }
//    }
}