#include "IDAPlugin.h"
#include "./Common/StringUtils.h"
#include "./VmpCore/VmpReEngine.h"
#include "./Manager/VmpVersionManager.h"

#define ACTION_MarkVmpEntry "Revampire::MarkVmpEntry"
#define ACTION_VMP350		"Revampire::VMP350"
#define ACTION_DECOMPILE    "Revampire::Decompile"

#ifdef DeveloperMode
#pragma optimize("", off) 
#endif

int MenuRevampire::activate(action_activation_ctx_t* ctx)
{
	std::string actionName = ctx->action;
	if (actionName == ACTION_MarkVmpEntry) {
		VmpReEngine::Instance().MarkVmpEntry(get_screen_ea());
		return 0x0;
	}
	if (actionName == ACTION_VMP350) {
		VmpVersionManager::SetVmpVersion(VmpVersionManager::VMP_350);
		VmpReEngine::Instance().PrintGraph(get_screen_ea());
		return 0x0;
	}
	if (actionName == ACTION_DECOMPILE) {
		qstring strStartAddr = ctx->widget_title.substr(4);
		size_t startAddr = std::stoull(strStartAddr.c_str(), 0, 16);
		VmpReEngine::Instance().Decompile(startAddr);
	}
	return 0x0;
}

MenuRevampire::MenuRevampire(IDAPlugin* plugin)
{
	ida = plugin;

	const action_desc_t actMarkVmpEntry = {
sizeof(action_desc_t),ACTION_MarkVmpEntry,"Mark as VmEntry",this,
ida,nullptr,nullptr,0,ADF_OT_PLUGMOD };
	register_action(actMarkVmpEntry);

	const action_desc_t actExecuteVmp350 = {
	sizeof(action_desc_t),ACTION_VMP350,"Execute Vmp 3.5.0",this,
	ida,nullptr,nullptr,0,ADF_OT_PLUGMOD };
	register_action(actExecuteVmp350);

	const action_desc_t actDecompileVmp = {
sizeof(action_desc_t),ACTION_DECOMPILE,"Decompile",this,
ida,nullptr,nullptr,0,ADF_OT_PLUGMOD };
	register_action(actDecompileVmp);
}

MenuRevampire::~MenuRevampire()
{
	unregister_action(ACTION_VMP350);
	unregister_action(ACTION_MarkVmpEntry);
	unregister_action(ACTION_DECOMPILE);
}

void MenuRevampire::AttachMainMenu(TWidget* view, TPopupMenu* p)
{
	attach_action_to_popup(view, p, ACTION_MarkVmpEntry, "Revampire/", SETMENU_INS);
	attach_action_to_popup(view, p, ACTION_VMP350, "Revampire/", SETMENU_INS);
}

void MenuRevampire::AttachGraphMenu(TWidget* view, TPopupMenu* p)
{
	attach_action_to_popup(view, p, ACTION_DECOMPILE, "", SETMENU_INS);
}

action_state_t idaapi MenuRevampire::update(action_update_ctx_t* ctx)
{
	return AST_ENABLE_ALWAYS;
}

ssize_t PluginUI_Callback(void* ud, int notification_code, va_list va)
{
	IDAPlugin* ida = (IDAPlugin*)(ud);
	if (notification_code == ui_populating_widget_popup) {
		TWidget* view = va_arg(va, TWidget*);
		TPopupMenu* p = va_arg(va, TPopupMenu*);
		int widgetType = get_widget_type(view);
		if (BWN_DISASM == widgetType) {
			ida->gMenu_Revampire.AttachMainMenu(view, p);
		}
		else if (BWN_PSEUDOCODE == widgetType) {
			ida->gMenu_Revampire.AttachMainMenu(view, p);
		}
		else if (BWN_CUSTVIEW == widgetType) {
			qstring widgetTitle;
			get_widget_title(&widgetTitle, view);
			if (widgetTitle.find("vmp_") == 0) {
				ida->gMenu_Revampire.AttachGraphMenu(view, p);
			}
		}
	}
	return 0;
}

IDAPlugin::IDAPlugin() :gMenu_Revampire(this)
{
    msg("[Revampire] plugin 0.1 loaded\n");
    msg("[Revampire] https://github.com/fjqisba/VmpHelper\n");
    hook_to_notification_point(HT_UI, PluginUI_Callback, this);
}

IDAPlugin::~IDAPlugin()
{
	unhook_from_notification_point(HT_UI, PluginUI_Callback, this);
}

bool idaapi IDAPlugin::run(size_t)
{
	return true;
}

#ifdef DeveloperMode
#pragma optimize("", on) 
#endif