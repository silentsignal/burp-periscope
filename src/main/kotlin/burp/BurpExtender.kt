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
            val excludeMenuItems = mutableListOf<JMenuItem>()
            for (length in ps downTo 1) {
                val postfix = parts.subList(ps - length, ps).joinToString(".")
                val mi = JMenuItem("Add *.$postfix to scope (all protocols, ports and paths)")
                mi.addActionListener { addToScope(postfix) }
                addMenuItems.add(mi)
                val miExclude = JMenuItem("Exclude *.$postfix from scope (all protocols, ports and paths)")
                miExclude.addActionListener { excludeFromScope(postfix) }
                excludeMenuItems.add(miExclude)
            }
            addMenuItems.forEach { menuItem -> topLevel.add(menuItem) }
            topLevel.addSeparator()
            excludeMenuItems.forEach { menuItem -> topLevel.add(menuItem) }
        }
        return topLevel
    }

    private fun addToScope(postfix: String) {
        scope = Scope(include = scope.include + listOf(ScopeItem.fromPostfix(postfix)), exclude = scope.exclude)
    }

    private fun excludeFromScope(postfix: String) {
        scope = Scope(include = scope.include, exclude = scope.exclude + listOf(ScopeItem.fromPostfix(postfix)))
    }

    private var scope: Scope
        get() = JSON.parse(Root.serializer(), callbacks.saveConfigAsJson("target.scope")).target.scope
        set(value) = callbacks.loadConfigFromJson(JSON.stringify(Root.serializer(), Root(Target(value))))
}

@Serializable
data class ScopeItem(val enabled: Boolean, @Optional val host: String = "", @Optional val file: String = "",
                   @Optional val protocol: String = "any", @Optional val port: String = "") {
    companion object {
        fun fromPostfix(postfix: String) = ScopeItem(enabled = true, host = "\\.${Regex.escape(postfix)}$")
    }
}

@Serializable data class Scope(val include: List<ScopeItem>, val exclude: List<ScopeItem>, val advanced_mode: Boolean = true)
@Serializable data class Target(val scope: Scope)
@Serializable data class Root(val target: Target)