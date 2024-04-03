#pragma once
#include <hexrays.hpp>

class IDAPlugin;
class MenuRevampire :public action_handler_t
{
public:
	MenuRevampire(IDAPlugin* plugin);
	~MenuRevampire();
	void AttachToPopupMenu(TWidget* view, TPopupMenu* p);
private:
	int activate(action_activation_ctx_t* ctx)override;
	action_state_t idaapi update(action_update_ctx_t* ctx) override;
private:
	IDAPlugin* ida;
};

class IDAPlugin :public plugmod_t
{
public:
    IDAPlugin();
    ~IDAPlugin();
	virtual bool idaapi run(size_t) override;
public:
	MenuRevampire gMenu_Revampire;
};