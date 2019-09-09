import io.gatling.core.Predef._
import com.tr.nest.crypto._
//import com.tr.nest.crypto.NestKeyPair._
import org.bouncycastle.util.encoders._
import io.gatling.http.Predef._

class main extends Simulation {
    setUp(
    Order.scnOrder.inject(atOnceUsers(Constants.numberOfUsers))
      // Order.scnFeed.inject(atOnceUsers(Constants.numberOfUsers))

    .protocols(Constants.httpProtocol.inferHtmlResources()))
    .pauses(constantPauses)
    .maxDuration(Constants.duration)
    .assertions(
      global.responseTime.max.lt(Constants.responseTimeMs),
      global.successfulRequests.percent.gt(Constants.responseSuccessPercentage)
    )
}
