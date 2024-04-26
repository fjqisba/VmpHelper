#pragma once
#include "../Ghidra/action.hh"

namespace ghidra
{
    //针对handler定制的死代码消除
    class ActionVmpHandlerDeadCode : public Action {
    public:
        ActionVmpHandlerDeadCode(const string& g, AddrSpace* ss) : Action(0, "handlerdeadcode", g) { stackspace = ss; }	///< Constructor
        virtual Action* clone(const ActionGroupList& grouplist) const {
            if (!grouplist.contains(getGroup())) return (Action*)0;
            return new ActionVmpHandlerDeadCode(getGroup(), stackspace);
        }
        virtual int4 apply(Funcdata& data);
    private:
        AddrSpace* stackspace;		///< Stack space associated with stack-pointer register
    };

	//Vmp函数启动
	class ActionVmpStart : public Action {
	public:
		ActionVmpStart(const string& g) : Action(0, "vmpstart", g) {}		///< Constructor
		virtual Action* clone(const ActionGroupList& grouplist) const {
			if (!grouplist.contains(getGroup())) return (Action*)0;
			return new ActionVmpStart(getGroup());
		}
        virtual int4 apply(Funcdata& data);
	};

	class ActionFixStack : public Action {
	public:
		ActionFixStack(const string& g) : Action(0, "fixstack", g) {}		///< Constructor
		virtual Action* clone(const ActionGroupList& grouplist) const {
			if (!grouplist.contains(getGroup())) return (Action*)0;
			return new ActionFixStack(getGroup());
		}
		virtual int4 apply(Funcdata& data);
	};
}