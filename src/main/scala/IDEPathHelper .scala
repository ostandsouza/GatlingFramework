import java.nio.file.Path
import java.util.Properties
//import io.gatling.core.util.PathHelper._
import io.gatling.commons.util.PathHelper._

object IDEPathHelper  {
  
  //var properties : Properties = null
  val url = getClass.getResource("/my.properties")
  val properties = new Properties()
  properties.load(this.getClass().getResourceAsStream("project.properties"));
  val gatlingConfUrl : Path = getClass.getClassLoader.getResource("gatling.conf").toURI()
	val projectRootDir = properties.get("project.basedir")
	  println("projectRootDir",projectRootDir)

		val mavenSourcesDirectory = """C:/java/RestApi/src/main/scala"""
	val mavenResourcesDirectory = """C:/java/RestApi/src/main/resources"""
	val mavenTargetDirectory = """C:/java/RestApi/target"""
	val mavenBinariesDirectory = """C:/java/RestApi/target/test-classes"""

	val dataDirectory = """C:/java/RestApi/src/main/resources/data"""
	val bodiesDirectory = """C:/java/RestApi/src/main/resources/data/bodies"""
	val recorderOutputDirectory = mavenSourcesDirectory
	println("recorderOutputDirectory",recorderOutputDirectory)
	val resultsDirectory = """C:/java/RestApi/target/results"""

	val recorderConfigFile = """C:/java/RestApi/src/main/resources/recorder.conf"""
	
}