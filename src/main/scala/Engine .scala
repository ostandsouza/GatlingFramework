import io.gatling.app.Gatling
import io.gatling.core.config.GatlingPropertiesBuilder

object Engine extends App {
  
  val props = new GatlingPropertiesBuilder
  props.simulationsDirectory("com.gatling.apitest")
  //props.simulationClass("com.gatling.apitest.main")//(IDEPathHelper.recorderOutputDirectory.toString)
	props.resourcesDirectory(IDEPathHelper.mavenBinariesDirectory.toString)
	props.resultsDirectory(IDEPathHelper.resultsDirectory.toString)
	//props.bodiesDirectory(IDEPathHelper.bodiesDirectory.toString)
	props.binariesDirectory(IDEPathHelper.mavenBinariesDirectory.toString)

	Gatling.fromMap(props.build)
}