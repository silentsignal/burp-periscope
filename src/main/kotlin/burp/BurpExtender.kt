package burp

import javax.swing.JMenu
import javax.swing.JMenuItem
import kotlinx.serialization.json.JSON
import kotlinx.serialization.Optional
import kotlinx.serialization.Serializable

const val NAME = "Periscope"

class BurpExtender : IBurpExtender {

    private lateinit var callbacks: IBurpExtenderCallbacks
    private lateinit var helpers: IExtensionHelpers

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        helpers = callbacks.helpers

        callbacks.setExtensionName(NAME)
        callbacks.registerContextMenuFactory {
            val messages = it.selectedMessages
            if (messages.isNullOrEmpty()) return@registerContextMenuFactory emptyList()
            val topLevel = generateContextMenu(messages)
            return@registerContextMenuFactory listOf(topLevel)
        }
    }

    private fun generateContextMenu(messages: Array<IHttpRequestResponse>): JMenuItem {
        val topLevel = JMenu(NAME)
        messages.map(helpers::analyzeRequest).forEach {
            val parts = it.url.host.split('.')
            val ps = parts.size
            val addMenuItems = mutableListOf<JMenuItem>()
            for (length in ps downTo 1) {
                val postfix = parts.subList(ps - length, ps).joinToString(".")
                val mi = JMenuItem("Add *.$postfix to scope (all protocols, ports and paths)")
                mi.addActionListener { addToScope(postfix) }
                addMenuItems.add(mi)
            }
            addMenuItems.forEach { menuItem -> topLevel.add(menuItem) }
        }
        return topLevel
    }

    private fun addToScope(postfix: String) {
        val newItem = ScopeItem(enabled = true, host = "\\.${Regex.escape(postfix)}$")
        config = Root(Target(Scope(config.target.scope.include + listOf(newItem))))
    }

    private var config: Root
        get() = JSON.parse(Root.serializer(), callbacks.saveConfigAsJson("target.scope"))
        set(value) = callbacks.loadConfigFromJson(JSON.stringify(Root.serializer(), value))
}

@Serializable
data class ScopeItem(val enabled: Boolean, @Optional val host: String = "", @Optional val file: String = "",
                   @Optional val protocol: String = "any", @Optional val port: String = "")

@Serializable data class Scope(val include: List<ScopeItem>)
@Serializable data class Target(val scope: Scope)
@Serializable data class Root(val target: Target)