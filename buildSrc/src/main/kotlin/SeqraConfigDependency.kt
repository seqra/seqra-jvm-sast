import org.gradle.api.Project
import org.seqra.common.SeqraDependency

object SeqraConfigDependency : SeqraDependency {
    override val seqraRepository: String = "seqra-config"
    override val versionProperty: String = "seqraConfigLibraryVersion"

    val Project.seqraConfig: String
        get() = propertyDep(group = "org.seqra.config", name = "seqra-config")
}
