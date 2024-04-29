/*
 *      Interactive disassembler (IDA).
 *      Copyright (c) 1990-2023 Hex-Rays
 *      ALL RIGHTS RESERVED.
 *
 */

/*! \file kernwin.hpp

  \brief Defines the interface between the kernel and the UI.

  It contains:
          - the UI dispatcher notification codes (::ui_notification_t)
          - convenience functions for UI services
          - structures which hold information about the
            lines (disassembly, structures, enums) generated
            by the kernel
          - functions to interact with the user (dialog boxes)
          - some string and conversion functions.
*/

#ifndef __KERNWIN_HPP
#define __KERNWIN_HPP
//-V:DEF_SET_METHOD:524 equivalent function bodies
//-V:DEF_FIELD_METHOD:524
//-V:place_t:730 not all members of a class are initialized inside the constructor
//-V:structplace_t:730
//-V:idaplace_t:730
//-V:enumplace_t:730

#ifndef SWIG
typedef uchar color_t;          ///< see <lines.hpp>
typedef uval_t bmask_t;         ///< see <enum.hpp>
typedef tid_t enum_t;           ///< see <enum.hpp>
struct rangevec_t;              ///< see <range.hpp>
class location_t;               ///< see <moves.hpp>
struct lochist_entry_t;         ///< see <moves.hpp>
struct strwinsetup_t;           ///< see <strlist.hpp>
struct renderer_info_t;         ///< see <moves.hpp>
struct segm_move_infos_t;       ///< see <moves.hpp>
struct load_info_t;             ///< see <loader.hpp>
#endif // SWIG

/// Message box kinds
enum mbox_kind_t
{
  mbox_internal,                ///< internal error
  mbox_info,
  mbox_warning,
  mbox_error,
  mbox_nomem,
  mbox_feedback,
  mbox_readerror,
  mbox_writeerror,
  mbox_filestruct,
  mbox_wait,
  mbox_hide,
  mbox_replace,
};


/// List chooser types
enum choose_type_t
{
  chtype_generic,                ///< the generic choose() function
  chtype_idasgn,                 ///< see choose_idasgn()
  chtype_entry,                  ///< see choose_entry()
  chtype_name,                   ///< see choose_name()
  chtype_stkvar_xref,            ///< see choose_stkvar_xref()
  chtype_xref,                   ///< see choose_xref()
  chtype_enum,                   ///< see choose_enum()
  chtype_enum_by_value,          ///< Deprecated. See ::chtype_enum_by_value_and_size
  chtype_func,                   ///< see choose_func()
  chtype_segm,                   ///< see choose_segm()
  chtype_struc,                  ///< see choose_struc()
  chtype_strpath,                ///< see choose_struc_path()
  chtype_idatil,                 ///< see choose_til()
  chtype_enum_by_value_and_size, ///< see choose_enum_by_value()
  chtype_srcp,                   ///< see choose_srcp()
};


enum beep_t             ///< Beep types
{
  beep_default = 0
};


// Notify UI about various events. The kernel will call this function
// when something interesting for the UI happens.
// The UI should avoid calling the kernel from this callback.

class func_t;
class segment_t;
struct sreg_range_t;
class struc_t;
class member_t;
class plugin_t;
struct plugmod_t;
struct procmod_t;
class minsn_t;
class idc_value_t;
class linput_t;
class snapshot_t;

/// TWidget renderer type
enum tcc_renderer_type_t
{
  TCCRT_INVALID = 0,        ///< invalid
  TCCRT_FLAT,               ///< flat view
  TCCRT_GRAPH,              ///< graph view
  TCCRT_PROXIMITY           ///< proximity view
};

/// TWidget ::place_t type
enum tcc_place_type_t
{
  TCCPT_INVALID = 0,        ///< invalid
  TCCPT_PLACE,              ///< ::place_t
  TCCPT_SIMPLELINE_PLACE,   ///< ::simpleline_place_t
  TCCPT_IDAPLACE,           ///< ::idaplace_t
  TCCPT_ENUMPLACE,          ///< ::enumplace_t
  TCCPT_STRUCTPLACE         ///< ::structplace_t
};

/// Represents mouse button for view_mouse_event_t objects
enum vme_button_t
{
  VME_UNKNOWN,              ///< unknown mouse button
  VME_LEFT_BUTTON,          ///< left mouse button
  VME_RIGHT_BUTTON,         ///< right mouse button
  VME_MID_BUTTON,           ///< middle mouse button
};

//-------------------------------------------------------------------------
/// \defgroup SETMENU_ Set menu flags
/// Passed as 'flags' parameter to attach_action_to_menu()
/// In case menupath == nullptr new item will be added to the end of menu even when
/// SETMENU_APP is not set. SETMENU_FIRST can be used to change this behaviour
/// Note: The upper 16 bits are reserved for UI internal use.
//@{
#define SETMENU_POSMASK       0x3
#define SETMENU_INS           0x0 ///< add menu item before the specified path (default)
#define SETMENU_APP           0x1 ///< add menu item after the specified path
#define SETMENU_FIRST         0x2 ///< add item to the beginning of menu
#define SETMENU_ENSURE_SEP    0x8 ///< make sure there is a separator before the action
//@}

/// \defgroup CREATETB_ create toolbar flags
/// Passed as 'flags' parameter to create_toolbar()
//@{
#define CREATETB_ADV         0x1 ///< toolbar is for 'advanced mode' only
//@}

//-------------------------------------------------------------------------
/// \defgroup HIF_ set_highlight flags
/// Passed as 'flags' parameter to set_highlight()
//@{
#define HIF_IDENTIFIER   0x1  ///< text is an identifier (i.e., when searching for the current highlight, SEARCH_IDENT will be used)
#define HIF_REGISTER     0x2  ///< text represents a register (aliases/subregisters will be highlit as well)
#define HIF_LOCKED       0x4  ///< locked; clicking/moving the cursor around doesn't change the highlight
#define HIF_NOCASE       0x8  ///< case insensitive

                         // bits 27-31 reserved
#define HIF_USE_SLOT     (1 << 27) ///< use the given number, or just use the "floating" highlight
#define HIF_SLOT_SHIFT   28        ///< position of the 3 top bits specifying which highlight to use
#define HIF_GET_SLOT(flags) (((flags) >> HIF_SLOT_SHIFT) & 0x7) ///< retrieve the highlight number to use (if HIF_USE_SLOT)

                         // convenience constants
                         // (not a macro HIF_SLOT(n) because SWIG won't pick it up for IDAPython)
#define HIF_SLOT_0       (HIF_USE_SLOT | (0 << HIF_SLOT_SHIFT)) ///< operate on slot 0
#define HIF_SLOT_1       (HIF_USE_SLOT | (1 << HIF_SLOT_SHIFT)) ///< operate on slot 1
#define HIF_SLOT_2       (HIF_USE_SLOT | (2 << HIF_SLOT_SHIFT)) ///< operate on slot 2
#define HIF_SLOT_3       (HIF_USE_SLOT | (3 << HIF_SLOT_SHIFT)) ///< operate on slot 3
#define HIF_SLOT_4       (HIF_USE_SLOT | (4 << HIF_SLOT_SHIFT)) ///< operate on slot 4
#define HIF_SLOT_5       (HIF_USE_SLOT | (5 << HIF_SLOT_SHIFT)) ///< operate on slot 5
#define HIF_SLOT_6       (HIF_USE_SLOT | (6 << HIF_SLOT_SHIFT)) ///< operate on slot 6
#define HIF_SLOT_7       (HIF_USE_SLOT | (7 << HIF_SLOT_SHIFT)) ///< operate on slot 7
//@}

#define REG_HINTS_MARKER SCOLOR_ON "\x7F"
#define REG_HINTS_MARKER_LEN 2
#define SRCDBG_HINTS_MARKER SCOLOR_ON "\x7E"
#define SRCDBG_HINTS_MARKER_LEN 2


/// \defgroup CDVF_ Code viewer flags
/// passed as 'flags' parameter to create_code_viewer()
//@{
#define CDVF_NOLINES        0x0001    ///< don't show line numbers
#define CDVF_LINEICONS      0x0002    ///< icons can be drawn over the line control
#define CDVF_STATUSBAR      0x0004    ///< keep the status bar in the custom viewer
//@}

/// \defgroup IDCHK_ IDC hotkey error codes
/// return values for add_idc_hotkey()
//@{
#define IDCHK_OK        0       ///< ok
#define IDCHK_ARG       -1      ///< bad argument(s)
#define IDCHK_KEY       -2      ///< bad hotkey name
#define IDCHK_MAX       -3      ///< too many IDC hotkeys
//@}

/// \defgroup WIDGET_CLOSE Form close flags
/// passed as options to close_widget()
//@{
#define WCLS_SAVE           0x1 ///< save state in desktop config
#define WCLS_NO_CONTEXT     0x2 ///< don't change the current context (useful for toolbars)
#define WCLS_DONT_SAVE_SIZE 0x4 ///< don't save size of the window
#define WCLS_DELETE_LATER   0x8 ///< assign the deletion of the widget to the UI loop ///< \return void
#define WCLS_CLOSE_LATER WCLS_DELETE_LATER
//@}

/// \defgroup DP_ Docking positions
/// passed as 'orient' parameter to set_dock_pos()
//@{
#define DP_LEFT            0x0001 ///< Dock src_form to the left of dest_form
#define DP_TOP             0x0002 ///< Dock src_form above dest_form
#define DP_RIGHT           0x0004 ///< Dock src_form to the right of dest_form
#define DP_BOTTOM          0x0008 ///< Dock src_form below dest_form
#define DP_INSIDE          0x0010 ///< Create a new tab bar with both src_form and dest_form
#define DP_TAB             0x0040 ///< Place src_form into a tab next to dest_form,
                                  ///< if dest_form is in a tab bar
                                  ///< (otherwise the same as #DP_INSIDE)
#define DP_BEFORE          0x0020 ///< Place src_form before dst_form in the tab bar instead of after;
                                  ///< used with #DP_INSIDE or #DP_TAB.
#define DP_FLOATING        0x0080 ///< Make src_form floating
#define DP_SZHINT          0x0100 ///< When floating or in a splitter (i.e., not tabbed),
                                  ///< use the widget's size hint to determine the best
                                  ///< geometry (Qt only)
//@}

/// \defgroup CDVF_ Code viewer flags
/// passed as 'flags' parameter to create_code_viewer()
//@{
#define CDVF_NOLINES        0x0001    ///< don't show line numbers
#define CDVF_LINEICONS      0x0002    ///< icons can be drawn over the line control
#define CDVF_STATUSBAR      0x0004    ///< keep the status bar in the custom viewer
//@}

/// \defgroup SVF_ Source viewer creation flags
/// passed as 'flags' parameter to callback for ::ui_create_source_viewer
//@{
#define SVF_COPY_LINES  0x0000   ///< keep a local copy of '*lines'
#define SVF_LINES_BYPTR 0x0001   ///< remember the 'lines' ptr. do not make a copy of '*lines'
//@}

/// \defgroup CVNF_ Custom viewer navigation flags
/// passed as 'flags' parameter to custom_viewer_jump()
//@{
#define CVNF_LAZY (1 << 0) ///< try and move the cursor to a line displaying the
                           ///< place_t if possible. This might disregard the Y
                           ///< position in case of success
#define CVNF_JUMP (1 << 1) ///< push the current position in this viewer's
                           ///< lochist_t before going to the new location
#define CVNF_ACT  (1 << 2) ///< activate (i.e., switch to) the viewer.
                           ///< Activation is performed before the new
                           ///< lochist_entry_t instance is actually copied
                           ///< to the viewer's lochist_t (otherwise, if the
                           ///< viewer was invisible its on_location_changed()
                           ///< handler wouldn't be called.)
//@}
/// \defgroup WIDGET_OPEN Widget open flags
/// passed as options to open_form() and display_widget()
//@{
//
#define WOPN_RESTORE           0x00000004u ///< if the widget was the only widget in a floating area the
                                           ///< last time it was closed, it will be restored as
                                           ///< floating, with the same position+size as before
#define WOPN_PERSIST           0x00000040u ///< widget will remain available when starting or stopping debugger sessions
#define WOPN_CLOSED_BY_ESC     0x00000080u ///< override idagui.cfg:CLOSED_BY_ESC: esc will close
#define WOPN_NOT_CLOSED_BY_ESC 0x00000100u ///< override idagui.cfg:CLOSED_BY_ESC: esc will not close
#define WOPN_DP_MASK           0x0FFF0000u
#define WOPN_DP_SHIFT          16
#define WOPN_DP_LEFT           (DP_LEFT << WOPN_DP_SHIFT)
                                           ///< Dock widget to the left of dest_ctrl
#define WOPN_DP_TOP            (DP_TOP << WOPN_DP_SHIFT)
                                           ///< Dock widget above dest_ctrl
#define WOPN_DP_RIGHT          (DP_RIGHT << WOPN_DP_SHIFT)
                                           ///< Dock widget to the right of dest_ctrl
#define WOPN_DP_BOTTOM         (DP_BOTTOM << WOPN_DP_SHIFT)
                                           ///< Dock widget below dest_ctrl
#define WOPN_DP_INSIDE         (DP_INSIDE << WOPN_DP_SHIFT)
                                           ///< Create a new tab bar with both widget and dest_ctrl
#define WOPN_DP_TAB            (DP_TAB << WOPN_DP_SHIFT)
                                           ///< Place widget into a tab next to dest_ctrl,
                                           ///< if dest_ctrl is in a tab bar
                                           ///< (otherwise the same as #WOPN_DP_INSIDE)
#define WOPN_DP_BEFORE         (DP_BEFORE << WOPN_DP_SHIFT)
                                           ///< Place widget before dst_form in the tab bar instead of after;
                                           ///< used with #WOPN_DP_INSIDE and #WOPN_DP_TAB
#define WOPN_DP_FLOATING       (DP_FLOATING << WOPN_DP_SHIFT)
                                           ///< Make widget floating
#define WOPN_DP_SZHINT         (DP_SZHINT << WOPN_DP_SHIFT)
                                           ///< when floating or in a splitter (i.e., not tabbed),
                                           ///< use the widget's size hint to determine the best
                                           ///< geometry (Qt only)
#define WOPN_DP_INSIDE_BEFORE  (WOPN_DP_INSIDE | WOPN_DP_BEFORE)
#define WOPN_DP_TAB_BEFORE     (WOPN_DP_TAB | WOPN_DP_BEFORE)
#define WOPN_GET_DP(v)         (((v) & WOPN_DP_MASK) >> WOPN_DP_SHIFT)
//@}

/// \defgroup RENADDR_DIALOGS Dialogs for "Rename address"
//@{
#define RENADDR_IDA   0   ///< dialog for "IDA View"
#define RENADDR_HR    1   ///< dialog for "Pseudocode";
                          ///< additional flags:
                          ///< - 0x01 Library function
                          ///< - 0x02 Mark as decompiled
//@}

#ifndef SWIG
/// Callui return codes.
/// The size of this type should be 4 bytes at most,
/// otherwise different compilers return it differently
union callui_t
{
  bool cnd;
  char i8;
  int i;
  short i16;
  int32 i32;
  uchar u8;
  ushort u16;
  uint32 u32;
  char *cptr;
  void *vptr;
  ssize_t ssize;
  func_t *fptr;
  segment_t *segptr;
  struc_t *strptr;
  plugin_t *pluginptr;
  sreg_range_t *sraptr;
};

/// Events marked as 'ui:' should be used as a parameter to callui().
/// (See convenience functions like get_screen_ea())
/// Events marked as 'cb:' are designed to be callbacks and should not
/// be used in callui(). The user may hook to ::HT_UI events to catch them

enum ui_notification_t
{
  ui_null = 0,

  ui_range,             ///< cb: The disassembly range has been changed (\inf{min_ea} ... \inf{max_ea}).
                        ///< UI should redraw the scrollbars. See also: ::ui_lock_range_refresh
                        ///< \param none
                        ///< \return void

  ui_refresh_choosers,  ///< cb: The list (chooser) window contents have been changed (names, signatures, etc).
                        ///< UI should redraw them. Please consider request_refresh() instead
                        ///< \param none
                        ///< \return void

  ui_idcstart,          ///< cb: Start of IDC engine work.
                        ///< \param none
                        ///< \return void

  ui_idcstop,           ///< cb: Stop of IDC engine work.
                        ///< \param none
                        ///< \return void

  ui_suspend,           ///< cb: Suspend graphical interface.
                        ///< Only the text version.
                        ///< Interface should respond to it.
                        ///< \param none
                        ///< \return void

  ui_resume,            ///< cb: Resume the suspended graphical interface.
                        ///< Only the text version.
                        ///< Interface should respond to it
                        ///< \param none
                        ///< \return void

  ui_broadcast,         ///< cb: broadcast call
                        ///< \param magic (::int64) a magic number
                        ///< \param ... other parameters depend on the given magic
                        ///< modules may hook to this event and reply to the caller.
                        ///< for example, the decompiler uses it to communicate
                        ///< its entry point to other plugins

  ui_read_selection,    ///< ui: see read_selection()

  ui_read_range_selection,  ///< ui: see read_range_selection()

  ui_unmarksel,         ///< ui: see unmark_selection()

  ui_screenea,          ///< ui: see get_screen_ea()

  ui_saving,            ///< cb: The kernel is flushing its buffers to the disk.
                        ///< The user interface should save its state.
                        ///< Parameters: none
                        ///< Returns:    none

  ui_saved,             ///< cb: The kernel has saved the database.
                        ///< This callback just informs the interface.
                        ///< Note that at the time this notification is sent,
                        ///< the internal paths are not updated yet,
                        ///< and calling get_path(PATH_TYPE_IDB) will return
                        ///< the previous path.
                        ///< \param path (const char *) the database path
                        ///< \return void

  ui_refreshmarked,     ///< ui: see refresh_idaview()

  ui_refresh,           ///< ui: see refresh_idaview_anyway()

  ui_choose,            ///< ui: Allow the user to choose an object.
                        ///< Always use the helper inline functions for this code.
                        ///< See \ref ui_choose_funcs for a list of such functions.
                        ///< \param type  (::choose_type_t) type of chooser to display
                        ///< \param ... other parameters depend on the given type
                        ///< \return depends on the given type

  ui_close_chooser,     ///< ui: see close_chooser()

  ui_banner,            ///< ui: see banner()

  ui_setidle,           ///< ui: Set a function to call at idle times.
                        ///< \param func  (int (*)(void)) pointer to function that will be called
                        ///< \return void

  ui_database_closed,   ///< cb: The database has been closed.
                        ///< See also processor_t::closebase, it occurs earlier.
                        ///< See also ui_initing_database.
                        ///< This is not the same as IDA exiting. If you need
                        ///< to perform cleanup at the exiting time, use qatexit().
                        ///< \return void

  ui_beep,              ///< ui: see beep()

  ui_is_msg_inited,     ///< ui: see is_msg_inited()

  ui_msg,               ///< ui: Show a message in the message window.
                        ///< \param format  (const char *) format of message body
                        ///< \param va      (va_list) format args
                        ///< \return number of bytes output

  ui_mbox,              ///< ui: Show a message box.
                        ///< \param kind    (::mbox_kind_t)
                        ///< \param format  (const char *) format of message body
                        ///< \param va      (va_list]) format args
                        ///< \return void

  ui_clr_cancelled,     ///< ui: see clr_cancelled()

  ui_set_cancelled,     ///< ui: see set_cancelled()

  ui_test_cancelled,    ///< ui: see user_cancelled()

  ui_ask_buttons,       ///< ui: see ask_yn() and ask_buttons()

  ui_ask_file,          ///< ui: see ask_file()

  ui_ask_form,          ///< ui: see \ref FORM_C

  ui_ask_text,          ///< ui: see ask_text()

  ui_ask_str,           ///< ui: see ask_str()

  ui_ask_addr,          ///< ui: see ask_addr()

  ui_ask_seg,           ///< ui: see ask_seg()

  ui_ask_long,          ///< ui: see ask_long()

  ui_add_idckey,        ///< ui: see add_idc_hotkey()

  ui_obsolete_del_idckey,
                        ///< ui: see ui_del_idckey()

  ui_analyzer_options,  ///< ui: see analyzer_options()

  ui_load_file,         ///< ui: see ui_load_new_file()

  ui_run_dbg,           ///< ui: see ui_run_debugger()

  ui_get_cursor,        ///< ui: see get_cursor()

  ui_get_curline,       ///< ui: see get_curline()

  ui_copywarn,          ///< ui: see display_copyright_warning()

  ui_noabort,           ///< ui: Disable 'abort' menu item - the database was not compressed.
                        ///< \param none
                        ///< \return void

  ui_lock_range_refresh,///< ui: Lock the ui_range refreshes.
                        ///< The ranges will not be refreshed until the corresponding
                        ///< ::ui_unlock_range_refresh is issued.
                        ///< \param none
                        ///< \return void

  ui_unlock_range_refresh,///< ui: Unlock the ::ui_range refreshes.
                        ///< If the number of locks is back to zero, then refresh the ranges.
                        ///< \param none
                        ///< \return void

  ui_genfile_callback,  ///< cb: handle html generation.
                        ///< \param html_header_cb_t **
                        ///< \param html_footer_cb_t **
                        ///< \param html_line_cb_t **
                        ///< \return void

  ui_open_url,          ///< ui: see open_url()

  ui_hexdumpea,         ///< ui: Return the current address in a hex view.
                        ///< \param result       (::ea_t *)
                        ///< \param hexdump_num  (int)
                        ///< \return void

  ui_get_key_code,      ///< ui: see get_key_code()

  ui_setup_plugins_menu,///< ui: setup plugins submenu
                        ///< \param none
                        ///< \return void

  ui_get_kernel_version,///< ui: see get_kernel_version()

  ui_is_idaq,           ///< ui: see is_idaq()

  ui_refresh_navband,   ///< ui: see refresh_navband()

  ui_debugger_menu_change, ///< cb: debugger menu modification detected
                        ///< \param enable (bool)
                        ///<    true: debugger menu has been added, or a different debugger has been selected
                        ///<    false: debugger menu will be removed (user switched to "No debugger")
                        ///< \return void

  ui_get_curplace,      ///< ui: see get_custom_viewer_place(). See also ui_get_custom_viewer_location

  ui_obsolete_display_widget,
  ui_close_widget,       ///< ui: see close_widget()

  ui_activate_widget,   ///< ui: see activate_widget()

  ui_find_widget,       ///< ui: see find_widget()

  ui_get_current_widget,
                        ///< ui: see get_current_widget()

  ui_widget_visible,    ///< TWidget is displayed on the screen.
                        ///< Use this event to populate the window with controls
                        ///< \param widget (TWidget *)
                        ///< \return void

  ui_widget_closing,    ///< TWidget is about to close.
                        ///< This event precedes ui_widget_invisible. Use this
                        ///< to perform some possible actions relevant to
                        ///< the lifecycle of this widget
                        ///< \param widget (TWidget *)
                        ///< \return void

  ui_widget_invisible,  ///< TWidget is being closed.
                        ///< Use this event to destroy the window controls
                        ///< \param widget (TWidget *)
                        ///< \return void

  ui_get_ea_hint,       ///< cb: ui wants to display a simple hint for an address.
                        ///< Use this event to generate a custom hint
                        ///< See also more generic ::ui_get_item_hint
                        ///< \param buf      (::qstring *)
                        ///< \param ea       (::ea_t)
                        ///< \return true if generated a hint

  ui_get_item_hint,     ///< cb: ui wants to display multiline hint for an item.
                        ///< See also more generic ::ui_get_custom_viewer_hint
                        ///< \param[out] hint             (::qstring *) the output string
                        ///< \param ea                    (ea_t) or item id like a structure or enum member
                        ///< \param max_lines             (int) maximal number of lines
                        ///< \param[out] important_lines  (int *) number of important lines. if zero, output is ignored
                        ///< \return true if generated a hint

  ui_refresh_custom_viewer,
                        ///< ui: see refresh_custom_viewer()

  ui_destroy_custom_viewer,
                        ///< ui: see destroy_custom_viewer()

  ui_jump_in_custom_viewer,
                        ///< ui: see jumpto()

  ui_get_custom_viewer_curline,
                        ///< ui: see get_custom_viewer_curline()

  ui_get_current_viewer,///< ui: see get_current_viewer()

  ui_is_idaview,        ///< ui: see is_idaview()

  ui_get_custom_viewer_hint,
                        ///< cb: ui wants to display a hint for a viewer (idaview or custom).
                        ///< Every subscriber is supposed to append the hint lines
                        ///< to HINT and increment IMPORTANT_LINES accordingly.
                        ///< Completely overwriting the existing lines in HINT
                        ///< is possible but not recommended.
                        ///< If the REG_HINTS_MARKER sequence is found in the
                        ///< returned hints string, it will be replaced with the
                        ///< contents of the "regular" hints.
                        ///< If the SRCDBG_HINTS_MARKER sequence is found in the
                        ///< returned hints string, it will be replaced with the
                        ///< contents of the source-level debugger-generated hints.
                        ///< The following keywords might appear at the beginning of the
                        ///< returned hints:
                        ///< HIGHLIGHT text\n
                        ///<   where text will be highlighted
                        ///< CAPTION caption\n
                        ///<   caption for the hint widget
                        ///< \param[out] hint             (::qstring *) the output string,
                        ///<                              on input contains hints from the previous subscribes
                        ///< \param viewer                (TWidget*) viewer
                        ///< \param place                 (::place_t *) current position in the viewer
                        ///< \param[out] important_lines  (int *) number of important lines,
                        ///<                                     should be incremented,
                        ///<                                     if zero, the result is ignored
                        ///< \retval 0 continue collecting hints with other subscribers
                        ///< \retval 1 stop collecting hints

  ui_set_custom_viewer_range,
                        ///< ui: set_custom_viewer_range()

  ui_database_inited,   ///< cb: database initialization has completed.
                        ///< the kernel is about to run idc scripts
                        ///< \param is_new_database  (int)
                        ///< \param idc_script       (const char *) - may be nullptr
                        ///< \return void
                        ///< See also ui_initing_database.
                        ///< This event is called for both new and old databases.

  ui_ready_to_run,      ///< cb: all UI elements have been initialized.
                        ///< Automatic plugins may hook to this event to
                        ///< perform their tasks.
                        ///< \param none
                        ///< \return void

  ui_set_custom_viewer_handler,
                        ///< ui: see set_custom_viewer_handler().
                        ///< also see other examples in \ref ui_scvh_funcs

  ui_refresh_chooser,   ///< ui: see refresh_chooser()

  ui_open_builtin,      ///< ui: open a window of a built-in type. see \ref ui_open_builtin_funcs

  ui_preprocess_action, ///< cb: ida ui is about to handle a user action.
                        ///< \param name  (const char *) ui action name.
                        ///<                             these names can be looked up in ida[tg]ui.cfg
                        ///< \retval 0 ok
                        ///< \retval nonzero a plugin has handled the command

  ui_postprocess_action,///< cb: an ida ui action has been handled

  ui_set_custom_viewer_mode,
                        ///< ui: switch between graph/text modes.
                        ///< \param custom_viewer  (TWidget *)
                        ///< \param graph_view     (bool)
                        ///< \param silent         (bool)
                        ///< \return bool success

  ui_gen_disasm_text,   ///< ui: see gen_disasm_text()

  ui_gen_idanode_text,  ///< cb: generate disassembly text for a node.
                        ///< Plugins may intercept this event and provide
                        ///< custom text for an IDA graph node
                        ///< They may use gen_disasm_text() for that.
                        ///< \param text  (text_t *)
                        ///< \param fc    (qflow_chart_t *)
                        ///< \param node  (int)
                        ///< \return bool text_has_been_generated

  ui_install_cli,       ///< ui: see:
                        ///< install_command_interpreter(),
                        ///< remove_command_interpreter()

  ui_execute_sync,      ///< ui: see execute_sync()

  ui_get_chooser_obj,   ///< ui: see get_chooser_obj()

  ui_enable_chooser_item_attrs,
                        ///< ui: see enable_chooser_item_attrs()

  ui_get_chooser_item_attrs,
                        ///< cb: get item-specific attributes for a chooser.
                        ///< This callback is generated only after enable_chooser_attrs()
                        ///< \param chooser  (const ::chooser_base_t *)
                        ///< \param n        (::size_t)
                        ///< \param attrs    (::chooser_item_attrs_t *)
                        ///< \return void

  ui_set_dock_pos,      ///< ui: see set_dock_pos()

  ui_get_opnum,         ///< ui: see get_opnum()

  ui_install_custom_datatype_menu,
                        ///< ui: install/remove custom data type menu item.
                        ///< \param dtid     (int) data type id
                        ///< \param install  (bool)
                        ///< \return success

  ui_install_custom_optype_menu,
                        ///< ui: install/remove custom operand type menu item.
                        ///< \param fid      (int) format id
                        ///< \param install  (bool)
                        ///< \return success

  ui_get_range_marker,  ///< ui: Get pointer to function.
                        ///< see mark_range_for_refresh(ea_t, asize_t).
                        ///< This function will be called by the kernel when the
                        ///< database is changed
                        ///< \param none
                        ///< \return vptr: (idaapi*marker)(ea_t ea, asize_t) or nullptr

  ui_lookup_key_code,   ///< ui: see lookup_key_code()

  ui_load_custom_icon_file,
                        ///< ui: see load_custom_icon(const char *)

  ui_load_custom_icon,  ///< ui: see load_custom_icon(const void *, unsigned int, const char *)

  ui_free_custom_icon,  ///< ui: see free_custom_icon()

  ui_process_action,    ///< ui: see process_ui_action()

  ui_create_code_viewer,///< ui: see create_code_viewer()

  ui_addons,            ///< ui: see \ref ui_addons_funcs

  ui_execute_ui_requests,
                        ///< ui: see execute_ui_requests(ui_request_t, ...)

  ui_execute_ui_requests_list,
                        ///< ui: see execute_ui_requests(ui_requests_t)

  ui_register_timer,    ///< ui: see register_timer()

  ui_unregister_timer,  ///< ui: see unregister_timer()

  ui_take_database_snapshot,
                        ///< ui: see take_database_snapshot()

  ui_restore_database_snapshot,
                        ///< ui: see restore_database_snapshot()

  ui_set_code_viewer_line_handlers,
                        ///< ui: see set_code_viewer_line_handlers()

  ui_obsolete_refresh_custom_code_viewer,

  ui_create_source_viewer,
                        ///< ui: Create new source viewer.
                        ///< \param top_tl    (TWidget **) toplevel widget of created source viewer (can be nullptr)
                        ///< \param parent    (TWidget *)
                        ///< \param custview  (TWidget *)
                        ///< \param path      (const char *)
                        ///< \param lines     (strvec_t *)
                        ///< \param lnnum     (int)
                        ///< \param colnum    (int)
                        ///< \param flags     (int) (\ref SVF_)
                        ///< \return source_view_t *

  ui_get_tab_size,      ///< ui: see get_tab_size()

  ui_repaint_qwidget,   ///< ui: see repaint_custom_viewer()

  ui_custom_viewer_set_userdata,
                        ///< ui: Change ::place_t user data for a custom view.
                        ///< \param custom_viewer  (TWidget *)
                        ///< \param user_data      (void *)
                        ///< \return old user_data

  ui_jumpto,            ///< ui: see jumpto(ea_t, int, int)

  ui_cancel_exec_request,
                        ///< ui: see cancel_exec_request()

  ui_open_form,         ///< ui: see vopen_form()

  ui_unrecognized_config_directive,
                        ///< ui: Possibly handle an extra config directive,
                        ///<   passed through '-d' or '-D'.
                        ///< \param directive  (const char *) The config directive
                        ///< \return char * - one of \ref IDPOPT_RET
                        ///< See also register_cfgopts, which is better

  ui_get_output_cursor, ///< ui: see get_output_cursor()

  ui_get_output_curline,///< ui: see get_output_curline()

  ui_get_output_selected_text,
                        ///< ui: see get_output_selected_text()

  ui_get_renderer_type, ///< ui: see get_view_renderer_type()

  ui_set_renderer_type, ///< ui: see set_view_renderer_type()

  ui_get_viewer_user_data,
                        ///< ui: see get_viewer_user_data()

  ui_get_viewer_place_type,
                        ///< ui: see get_viewer_place_type()

  ui_ea_viewer_history_push_and_jump,
                        ///< ui: see ea_viewer_history_push_and_jump()

  ui_ea_viewer_history_info,
                        ///< ui: see get_ea_viewer_history_info()

  ui_register_action,
                        ///< ui: see register_action()

  ui_unregister_action,
                        ///< ui: see unregister_action()

  ui_attach_action_to_menu,
                        ///< ui: see attach_action_to_menu()

  ui_detach_action_from_menu,
                        ///< ui: see detach_action_from_menu()

  ui_attach_action_to_popup,
                        ///< ui: see attach_action_to_popup()

  ui_detach_action_from_popup,
                        ///< ui: see detach_action_from_popup()

  ui_attach_dynamic_action_to_popup,
                        ///< ui: see create attach_dynamic_action_to_popup()

  ui_attach_action_to_toolbar,
                        ///< ui: see attach_action_to_toolbar()

  ui_detach_action_from_toolbar,
                        ///< ui: see detach_action_from_toolbar()

  ui_updating_actions,  ///< cb: IDA is about to update all actions. If your plugin
                        ///< needs to perform expensive operations more than once
                        ///< (e.g., once per action it registers), you should do them
                        ///< only once, right away.
                        ///< \param ctx  (::action_update_ctx_t *)
                        ///< \return void

  ui_updated_actions,   ///< cb: IDA is done updating actions.
                        ///< \param none
                        ///< \return void

  ui_populating_widget_popup,
                        ///< cb: IDA is populating the context menu for a widget.
                        ///< This is your chance to attach_action_to_popup().
                        ///<
                        ///< Have a look at ui_finish_populating_widget_popup,
                        ///< if you want to augment the
                        ///< context menu with your own actions after the menu
                        ///< has had a chance to be properly populated by the
                        ///< owning component or plugin (which typically does it
                        ///< on ui_populating_widget_popup.)
                        ///<
                        ///< \param widget        (TWidget *)
                        ///< \param popup_handle  (TPopupMenu *)
                        ///< \param ctx           (const action_activation_ctx_t *)
                        ///< \return void
                        ///<
                        ///< ui: see ui_finish_populating_widget_popup

  ui_finish_populating_widget_popup,
                        ///< cb: IDA is about to be done populating the
                        ///< context menu for a widget.
                        ///< This is your chance to attach_action_to_popup().
                        ///<
                        ///< \param widget        (TWidget *)
                        ///< \param popup_handle  (TPopupMenu *)
                        ///< \param ctx           (const action_activation_ctx_t *)
                        ///< \return void
                        ///<
                        ///< ui: see ui_populating_widget_popup

  ui_update_action_attr,
                        ///< ui: see \ref ui_uaa_funcs

  ui_get_action_attr,   ///< ui: see \ref ui_gaa_funcs

  ui_plugin_loaded,     ///< cb: The plugin was loaded in memory.
                        ///< \param plugin_info  (const ::plugin_info_t *)

  ui_plugin_unloading,  ///< cb: The plugin is about to be unloaded
                        ///< \param plugin_info  (const ::plugin_info_t *)

  ui_get_widget_type,  ///< ui: see get_widget_type()

  ui_current_widget_changed,
                        ///< cb: The currently-active TWidget changed.
                        ///< \param widget      (TWidget *)
                        ///< \param prev_widget (TWidget *)
                        ///< \return void

  ui_get_widget_title, ///< ui: see get_widget_title()

  ui_obsolete_get_user_strlist_options,
                        ///< ui: see get_user_strlist_options()

  ui_create_custom_viewer,
                        ///< ui: see create_viewer()

  ui_custom_viewer_jump,///< ui: set the current location, and have the viewer display it
                        ///< \param v     (TWidget *)
                        ///< \param loc   (const lochist_entry_t *)
                        ///< \param flags (uint32) or'ed combination of CVNF_* values
                        ///< \return success

  ui_set_custom_viewer_handlers,
                        ///< ui: see set_custom_viewer_handlers()

  ui_get_registered_actions,
                        ///< ui: see get_registered_actions()

  ui_create_toolbar,    ///< ui: see create_toolbar()
  ui_delete_toolbar,    ///< ui: see delete_toolbar()
  ui_create_menu,       ///< ui: see create_menu()
  ui_delete_menu,       ///< ui: see delete_menu()
  ui_obsolete_set_nav_colorizer,
  ui_get_chooser_data,  ///< ui: see get_chooser_data()
  ui_obsolete_get_highlight, ///< now ui_get_highlight_2
  ui_set_highlight,     ///< ui: see set_highlight()

  ui_set_mappings,      ///< ui: Show current memory mappings
                        ///<     and allow the user to change them.
  ui_create_empty_widget,
                        ///< ui: see create_empty_widget()

  ui_msg_clear,         ///< ui: see msg_clear()
  ui_msg_save,          ///< ui: see msg_save()
  ui_msg_get_lines,     ///< ui: see msg_get_lines()

  ui_chooser_default_enter,
                        ///< ui: jump to the address returned by get_ea() callback in the
                        ///< case of the non-modal choosers
                        ///< \param chooser  (const ::chooser_base_t *)
                        ///< \param n/sel    (::size_t *)     for chooser_t
                        ///<                 (::sizevec_t *)  for chooser_multi_t
                        ///< \return int     chooser_t::cbres_t

  ui_screen_ea_changed,
                        ///< cb: The "current address" changed
                        ///< \param ea          (ea_t)
                        ///< \param prev_ea     (ea_t)
                        ///< \return void

  ui_get_active_modal_widget,
                        ///< ui: see get_active_modal_widget()

  ui_navband_pixel,     ///< ui: see get_navband_pixel
  ui_navband_ea,        ///< ui: see get_navband_ea
  ui_get_window_id,     ///< ui: set get_window_id (GUI only)

  ui_create_desktop_widget,
                        ///< cb: create a widget, to be placed in the widget tree (at desktop-creation time.)
                        ///< \param title    (const char *)
                        ///< \param cfg      (const jobj_t *)
                        ///< \return TWidget * the created widget, or null

  ui_strchoose,         ///< ui: undocumented


  ui_set_nav_colorizer, ///< ui: see set_nav_colorizer()
  ui_display_widget,    ///< ui: see display_widget()

  ui_get_lines_rendering_info,
                          ///< cb: get lines rendering information
                          ///< \param out (lines_rendering_output_t *)
                          ///< \param widget (const TWidget *)
                          ///< \param info (const lines_rendering_input_t *)
                          ///< \return void

  ui_sync_sources,
                          ///< ui: [un]synchronize sources
                          ///< \param what (const sync_source_t *)
                          ///< \param with (const sync_source_t *)
                          ///< \param sync (bool)
                          ///< \return success

  ui_get_widget_config,   ///< cb: retrieve the widget configuration (it will be passed
                          ///< back at ui_create_desktop_widget-, and ui_set_widget_config-time)
                          ///< \param widget (const TWidget *)
                          ///< \param cfg (jobj_t *)
                          ///< \return void

  ui_set_widget_config,   ///< cb: set the widget configuration
                          ///< \param widget (const TWidget *)
                          ///< \param cfg (const jobj_t *)
                          ///< \return void

  ui_get_custom_viewer_location,
                          ///< ui: see get_custom_viewer_location()
                          ///< \param out (lochist_entry_t *)
                          ///< \param custom_viewer (TWidget *)
                          ///< \param mouse (bool)

  ui_initing_database,    ///< cb: database initialization has started.
                          ///< \return void
                          ///< See also ui_database_inited.
                          ///< This event is called for both new and old databases.

  ui_destroying_procmod,  ///< cb: The processor module is about to be destroyed
                          ///< \param procmod  (const ::procmod_t *)

  ui_destroying_plugmod,  ///< cb: The plugin object is about to be destroyed
                          ///< \param plugmod  (const ::plugmod_t *)
                          ///< \param entry  (const ::plugin_t *)

  ui_update_file_history, ///< ui: manipulate the file history
                          ///< \param add_path  (const char *)
                          ///< \param del_path  (const char *)

  ui_cancel_thread_exec_requests,
                          ///< ui: see cancel_thread_exec_requests()

  ui_get_synced_group,
                          ///< ui: see get_synced_group()

  ui_show_rename_dialog,  ///< ui: undocumented
                          ///< \return success

  ui_desktop_applied,     ///< cb: a desktop has been applied
                          ///< \param name      (const char *) the desktop name
                          ///< \param from_idb  (bool) the desktop was stored in the IDB (false if it comes from the registry)
                          ///< \param type      (int) the desktop type (1-disassembly, 2-debugger, 3-merge)

  ui_choose_bookmark,
                          ///< ui: modal chooser (legacy)
                          ///< \param n     (uint32 *) input: default slot, output: chosen bookmark index
                          ///< \param entry (const lochist_entry_t *) entry with place type
                          ///< \param ud    (void *) user data

  ui_get_custom_viewer_place_xcoord,
                          ///< ui: see get_custom_viewer_place_xcoord()

  ui_get_user_input_event,
                          ///< ui: see get_user_input_event()

  ui_get_highlight_2,     ///< ui: see get_highlight()

  ui_last,              ///< the last notification code

  ui_dbg_begin = 1000, ///< debugger callgates. should not be used directly, see dbg.hpp for details
  ui_dbg_run_requests = ui_dbg_begin,
  ui_dbg_get_running_request,
  ui_dbg_get_running_notification,
  ui_dbg_clear_requests_queue,
  ui_dbg_get_process_state,
  ui_dbg_start_process,
  ui_dbg_request_start_process,
  ui_dbg_suspend_process,
  ui_dbg_request_suspend_process,
  ui_dbg_continue_process,
  ui_dbg_request_continue_process,
  ui_dbg_exit_process,
  ui_dbg_request_exit_process,
  ui_dbg_get_thread_qty,
  ui_dbg_getn_thread,
  ui_dbg_select_thread,
  ui_dbg_request_select_thread,
  ui_dbg_step_into,
  ui_dbg_request_step_into,
  ui_dbg_step_over,
  ui_dbg_request_step_over,
  ui_dbg_run_to,
  ui_dbg_request_run_to,
  ui_dbg_step_until_ret,
  ui_dbg_request_step_until_ret,
  ui_dbg_get_bpt_qty,
  ui_dbg_add_oldbpt,
  ui_dbg_request_add_oldbpt,
  ui_dbg_del_oldbpt,
  ui_dbg_request_del_oldbpt,
  ui_dbg_enable_oldbpt,
  ui_dbg_request_enable_oldbpt,
  ui_dbg_set_trace_size,
  ui_dbg_clear_trace,
  ui_dbg_request_clear_trace,
  ui_dbg_is_step_trace_enabled,
  ui_dbg_enable_step_trace,
  ui_dbg_request_enable_step_trace,
  ui_dbg_get_step_trace_options,
  ui_dbg_set_step_trace_options,
  ui_dbg_request_set_step_trace_options,
  ui_dbg_is_insn_trace_enabled,
  ui_dbg_enable_insn_trace,
  ui_dbg_request_enable_insn_trace,
  ui_dbg_get_insn_trace_options,
  ui_dbg_set_insn_trace_options,
  ui_dbg_request_set_insn_trace_options,
  ui_dbg_is_func_trace_enabled,
  ui_dbg_enable_func_trace,
  ui_dbg_request_enable_func_trace,
  ui_dbg_get_func_trace_options,
  ui_dbg_set_func_trace_options,
  ui_dbg_request_set_func_trace_options,
  ui_dbg_get_tev_qty,
  ui_dbg_get_tev_info,
  ui_dbg_get_call_tev_callee,
  ui_dbg_get_ret_tev_return,
  ui_dbg_get_bpt_tev_ea,
  ui_dbg_get_reg_value_type,
  ui_dbg_get_processes,
  ui_dbg_attach_process,
  ui_dbg_request_attach_process,
  ui_dbg_detach_process,
  ui_dbg_request_detach_process,
  ui_dbg_get_first_module,
  ui_dbg_get_next_module,
  ui_dbg_bring_to_front,
  ui_dbg_get_current_thread,
  ui_dbg_wait_for_next_event,
  ui_dbg_get_debug_event,
  ui_dbg_set_debugger_options,
  ui_dbg_set_remote_debugger,
  ui_dbg_load_debugger,
  ui_dbg_retrieve_exceptions,
  ui_dbg_store_exceptions,
  ui_dbg_define_exception,
  ui_dbg_suspend_thread,
  ui_dbg_request_suspend_thread,
  ui_dbg_resume_thread,
  ui_dbg_request_resume_thread,
  ui_dbg_get_process_options,
  ui_dbg_check_bpt,
  ui_dbg_set_process_state,
  ui_dbg_get_manual_regions,
  ui_dbg_set_manual_regions,
  ui_dbg_enable_manual_regions,
  ui_dbg_set_process_options,
  ui_dbg_is_busy,
  ui_dbg_hide_all_bpts,
  ui_dbg_edit_manual_regions,
  ui_dbg_get_sp_val,
  ui_dbg_get_ip_val,
  ui_dbg_get_reg_val,
  ui_dbg_set_reg_val,
  ui_dbg_request_set_reg_val,
  ui_dbg_get_insn_tev_reg_val,
  ui_dbg_get_insn_tev_reg_result,
  ui_dbg_register_provider,
  ui_dbg_unregister_provider,
  ui_dbg_handle_debug_event,
  ui_dbg_add_vmod,
  ui_dbg_del_vmod,
  ui_dbg_compare_bpt_locs,
  ui_obsolete_dbg_save_bpts,
  ui_dbg_set_bptloc_string,
  ui_dbg_get_bptloc_string,
  ui_dbg_internal_appcall,
  ui_dbg_internal_cleanup_appcall,
  ui_dbg_internal_get_sreg_base,
  ui_dbg_internal_ioctl,
  ui_dbg_read_memory,
  ui_dbg_write_memory,
  ui_dbg_read_registers,
  ui_dbg_write_register,
  ui_dbg_get_memory_info,
  ui_dbg_get_event_cond,
  ui_dbg_set_event_cond,
  ui_dbg_enable_bpt,
  ui_dbg_request_enable_bpt,
  ui_dbg_del_bpt,
  ui_dbg_request_del_bpt,
  ui_dbg_map_source_path,
  ui_dbg_map_source_file_path,
  ui_dbg_modify_source_paths,
  ui_dbg_is_bblk_trace_enabled,
  ui_dbg_enable_bblk_trace,
  ui_dbg_request_enable_bblk_trace,
  ui_dbg_get_bblk_trace_options,
  ui_dbg_set_bblk_trace_options,
  ui_dbg_request_set_bblk_trace_options,
  // trace management
  ui_dbg_load_trace_file,
  ui_dbg_save_trace_file,
  ui_dbg_is_valid_trace_file,
  ui_dbg_set_trace_file_desc,
  ui_dbg_get_trace_file_desc,
  ui_dbg_choose_trace_file,
  ui_dbg_diff_trace_file,
  ui_dbg_graph_trace,
  ui_dbg_get_tev_memory_info,
  ui_dbg_get_tev_event,
  ui_dbg_get_insn_tev_reg_mem,
  // breakpoint management (new codes were introduced in v6.3)
  ui_dbg_getn_bpt,
  ui_dbg_get_bpt,
  ui_dbg_find_bpt,
  ui_dbg_add_bpt,
  ui_dbg_request_add_bpt,
  ui_dbg_update_bpt,
  ui_dbg_for_all_bpts,
  ui_dbg_get_tev_ea,
  ui_dbg_get_tev_type,
  ui_dbg_get_tev_tid,
  ui_dbg_get_trace_base_address,
  // calluis for creating traces from scratch (added in 6.4)
  ui_dbg_set_trace_base_address,
  ui_dbg_add_tev,
  ui_dbg_add_insn_tev,
  ui_dbg_add_call_tev,
  ui_dbg_add_ret_tev,
  ui_dbg_add_bpt_tev,
  ui_dbg_add_debug_event,
  ui_dbg_add_thread,
  ui_dbg_del_thread,
  ui_dbg_add_many_tevs,
  ui_dbg_set_bpt_group,
  ui_dbg_set_highlight_trace_options,
  ui_dbg_set_trace_platform,
  ui_dbg_get_trace_platform,
  // added in 6.6
  ui_dbg_internal_get_elang,
  ui_dbg_internal_set_elang,

  // added in 6.7
  ui_dbg_load_dbg_dbginfo,
  ui_dbg_set_resume_mode,
  ui_dbg_request_set_resume_mode,
  ui_dbg_set_bptloc_group,
  ui_dbg_list_bptgrps,
  ui_dbg_rename_bptgrp,
  ui_dbg_del_bptgrp,
  ui_dbg_get_grp_bpts,
  ui_dbg_get_bpt_group,
  ui_dbg_change_bptlocs,

  // added in 7.1
  ui_dbg_collect_stack_trace,
  ui_dbg_get_module_info,

  // source-level debugging
  ui_dbg_get_srcinfo_provider,
  ui_dbg_get_global_var,
  ui_dbg_get_local_var,
  ui_dbg_get_local_vars,
  ui_dbg_add_path_mapping,
  ui_dbg_get_current_source_file,
  ui_dbg_get_current_source_line,

  ui_dbg_srcdbg_step_into,
  ui_dbg_srcdbg_request_step_into,
  ui_dbg_srcdbg_step_over,
  ui_dbg_srcdbg_request_step_over,
  ui_dbg_srcdbg_step_until_ret,
  ui_dbg_srcdbg_request_step_until_ret,

  ui_dbg_getn_thread_name,
  ui_dbg_bin_search,

  ui_dbg_get_insn_tev_reg_val_i,
  ui_dbg_get_insn_tev_reg_result_i,
  ui_dbg_get_reg_val_i,
  ui_dbg_set_reg_val_i,

  ui_dbg_get_reg_info,

  ui_dbg_set_trace_dynamic_register_set,
  ui_dbg_get_trace_dynamic_register_set,

  // added in 7.7
  ui_dbg_enable_bptgrp,

  ui_dbg_end,

  // Debugging notifications
#ifdef _DEBUG
  debug_obsolete_assert_thread_waitready = ui_dbg_end
#endif
};


//--------------------------------------------------------------------------


/// Pointer to the user-interface dispatcher function.
/// This pointer is in the kernel

idaman callui_t ida_export_data (idaapi*callui)(ui_notification_t what,...);


/// After calling init_kernel() the ui must call this function.
/// It will open the database specified in the command line.
/// If the database did not exist, a new database will be created and
/// the input file will be loaded.
/// \return 0-ok, otherwise an exit code

idaman int ida_export init_database(int argc, const char *const *argv, int *newfile);


/// The database termination function.
/// This function should be called to close the database.

idaman void ida_export term_database(void);


/// See error()

idaman NORETURN AS_PRINTF(1, 0) void ida_export verror(const char *format, va_list va);


/// See show_hex()

idaman AS_PRINTF(3, 0) void ida_export vshow_hex(
        const void *dataptr,
        size_t len,
        const char *format,
        va_list va);


/// See show_hex_file()

idaman AS_PRINTF(4, 0) void ida_export vshow_hex_file(
        linput_t *li,
        int64 pos,
        size_t count,
        const char *format,
        va_list va);


#endif // SWIG

/// Get IDA kernel version (in a string like "5.1").

inline ssize_t get_kernel_version(char *buf, size_t bufsize)
{
  return callui(ui_get_kernel_version, buf, bufsize).ssize;
}

//--------------------------------------------------------------------------
//      K E R N E L   S E R V I C E S   F O R   U I
//--------------------------------------------------------------------------
//
// Generating text for the disassembly, enum, and structure windows.

/*! \brief Denotes a displayed line.

    (location_t would be a better name but it is too late to rename it now)

    An object may be displayed on one or more lines. All lines of an object are
    generated at once and kept in a linearray_t class.

    place_t is an abstract class, another class must be derived from it.                \n
    Currently the following classes are used in IDA:

                idaplace_t      - disassembly view                                      \n
                enumplace_t     - enum view                                             \n
                structplace_t   - structure view

    Example (idaplace_t):                                                               \verbatim

      004015AC
      004015AC loc_4015AC:                             ; CODE XREF: sub_4014B8+C5j
      004015AC                 xor     eax, eax                                         \endverbatim

    The first line is denoted by idaplace_t with ea=4015AC, lnnum=0                     \n
    The second line is denoted by idaplace_t with ea=4015AC, lnnum=1                    \n
    The third line is denoted by idaplace_t with ea=4015AC, lnnum=2

    NB: the place_t class may change in the future, do not rely on it
*/
class place_t
{
public:
  int lnnum;                      ///< Number of line within the current object
  place_t(void) {}                ///< Constructor
  place_t(int ln) : lnnum(ln) {}  ///< Constructor
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  /// Generate a short description of the location.
  /// This description is used on the status bar.
  /// \param vout     the output buffer
  /// \param ud       pointer to user-defined context data. Is supplied by ::linearray_t
  virtual void idaapi print(qstring *vout, void *ud) const = 0;

  /// Map the location to a number.
  /// This mapping is used to draw the vertical scrollbar.
  /// \param ud  pointer to user-defined context data. Is supplied by ::linearray_t
  virtual uval_t idaapi touval(void *ud) const                         = 0;

  /// Clone the location.
  /// \return a pointer to a copy of the current location in dynamic memory
  virtual place_t *idaapi clone(void) const                            = 0;

  /// Copy the specified location object to the current object
  virtual void idaapi copyfrom(const place_t *from)                    = 0;

  /// Map a number to a location.
  /// When the user clicks on the scrollbar and drags it, we need to determine
  /// the location corresponding to the new scrollbar position. This function
  /// is used to determine it. It builds a location object for the specified 'x'
  /// and returns a pointer to it.
  /// \param ud     pointer to user-defined context data. Is supplied by ::linearray_t
  /// \param x      number to map
  /// \param lnnum  line number to initialize 'lnnum'
  /// \return a freshly allocated object. See also PCF_MAKEPLACE_ALLOCATES
  virtual place_t *idaapi makeplace(void *ud, uval_t x, int lnnum) const= 0;

  /// Deprecated. Please consider compare2(const place_t *, void *) instead.
  virtual int idaapi compare(const place_t *t2) const                  = 0;

  /// Adjust the current location to point to a displayable object.
  /// This function validates the location and makes sure that it points to
  /// an existing object. For example, if the location points to the middle
  /// of an instruction, it will be adjusted to point to the beginning of the
  /// instruction.
  /// \param ud  pointer to user-defined context data. Is supplied by ::linearray_t
  virtual void idaapi adjust(void *ud)                                 = 0;

  /// Move to the previous displayable location.
  /// \param ud  pointer to user-defined context data. Is supplied by ::linearray_t
  /// \return success
  virtual bool idaapi prev(void *ud)                                   = 0;

  /// Move to the next displayable location.
  /// \param ud  pointer to user-defined context data. Is supplied by ::linearray_t
  /// \return success
  virtual bool idaapi next(void *ud)                                   = 0;

  /// Are we at the first displayable object?.
  /// \param ud   pointer to user-defined context data. Is supplied by ::linearray_t
  /// \return true if the current location points to the first displayable object
  virtual bool idaapi beginning(void *ud) const                        = 0;

  /// Are we at the last displayable object?.
  /// \param ud   pointer to user-defined context data. Is supplied by ::linearray_t
  /// \return true if the current location points to the last displayable object
  virtual bool idaapi ending(void *ud) const                           = 0;

  /// Generate text lines for the current location.
  /// \param out            storage for the lines
  /// \param out_deflnnum   pointer to the cell that will contain the number of
  ///                       the most 'interesting' generated line
  /// \param out_pfx_color  pointer to the cell that will contain the line prefix color
  /// \param out_bgcolor    pointer to the cell that will contain the background color
  /// \param ud             pointer to user-defined context data. Is supplied by linearray_t
  /// \param maxsize        the maximum number of lines to generate
  /// \return number of generated lines
  virtual int idaapi generate(
        qstrvec_t *out,
        int *out_deflnnum,
        color_t *out_pfx_color,
        bgcolor_t *out_bgcolor,
        void *ud,
        int maxsize) const = 0;

  /// Serialize this instance.
  /// It is fundamental that all instances of a particular subclass
  /// of of place_t occupy the same number of bytes when serialized.
  /// \param out   buffer to serialize into
  virtual void idaapi serialize(bytevec_t *out) const = 0;

  /// De-serialize into this instance.
  /// 'pptr' should be incremented by as many bytes as
  /// de-serialization consumed.
  /// \param pptr pointer to a serialized representation of a place_t of this type.
  /// \param end pointer to end of buffer.
  /// \return whether de-serialization was successful
  virtual bool idaapi deserialize(const uchar **pptr, const uchar *end) = 0;

  /// Get the place's ID (i.e., the value returned by register_place_class())
  /// \return the id
  virtual int idaapi id() const = 0;

  /// Get this place type name.
  /// All instances of a given class must return the same string.
  /// \return the place type name. Please try and pick something that is
  ///         not too generic, as it might clash w/ other plugins. A good
  ///         practice is to prefix the class name with the name
  ///         of your plugin. E.g., "myplugin:srcplace_t".
  virtual const char *idaapi name() const = 0;

  /// Map the location to an ea_t.
  /// \return the corresponding ea_t, or BADADDR;
  virtual ea_t idaapi toea() const { return BADADDR; }

  /// Rebase the place instance
  /// \param infos the segments that were moved
  /// \return true if place was rebased, false otherwise
  virtual bool idaapi rebase(const segm_move_infos_t & /*infos*/ ) { return true; }

  /// Visit this place, possibly 'unhiding' a section of text.
  /// If entering that place required some expanding, a place_t
  /// should be returned that represents that section, plus some
  /// flags for later use by 'leave()'.
  /// \param out_flags flags to be used together with the place_t that is
  ///                  returned, in order to restore the section to its
  ///                  original state when leave() is called.
  /// \return a place_t corresponding to the beginning of the section
  ///         of text that had to be expanded. That place_t's leave() will
  ///         be called with the flags contained in 'out_flags' when the user
  ///         navigates away from it.
  virtual place_t *idaapi enter(uint32 * /*out_flags*/) const { return nullptr; }

  /// Leave this place, possibly 'hiding' a section of text that was
  /// previously expanded (at enter()-time.)
  virtual void idaapi leave(uint32 /*flags*/) const {}

  /// Compare two locations except line numbers (lnnum).
  /// This function is used to organize loops.
  /// For example, if the user has selected an range, its boundaries are remembered
  /// as location objects. Any operation within the selection will have the following
  /// look: for ( loc=starting_location; loc < ending_location; loc.next() )
  /// In this loop, the comparison function is used.
  /// \param t2 the place to compare this one to.
  /// \param ud pointer to user-defined context data.
  /// \retval -1 if the current location is less than 't2'
  /// \retval  0 if the current location is equal to than 't2'
  /// \retval  1 if the current location is greater than 't2'
  virtual int idaapi compare2(const place_t *t2, void * /*ud*/) const { return compare(t2); }
};

#define DEFAULT_PLACE_LNNUM -1

/// compare places and their lnnums
idaman int ida_export l_compare(const place_t *t1, const place_t *t2);
idaman int ida_export l_compare2(const place_t *t1, const place_t *t2, void *ud);

#ifndef SWIG

//--------------------------------------------------------------------------
/// Helper to define exported functions for ::place_t implementations
#define define_place_exported_functions(classname)                                                      \
class classname;                                                                                        \
idaman void        ida_export classname ## __print(const classname *, qstring *, void*);                \
idaman uval_t      ida_export classname ## __touval(const classname *, void*);                           \
idaman place_t *   ida_export classname ## __clone(const classname *);                                  \
idaman void        ida_export classname ## __copyfrom(classname *, const place_t*);                      \
idaman place_t *   ida_export classname ## __makeplace(const classname *, void*, uval_t, int);             \
idaman int         ida_export classname ## __compare(const classname *, const place_t*);                 \
idaman int         ida_export classname ## __compare2(const classname *, const place_t*, void*);        \
idaman void        ida_export classname ## __adjust(classname *, void*);                                 \
idaman bool        ida_export classname ## __prev(classname *, void*);                                   \
idaman bool        ida_export classname ## __next(classname *, void*);                                   \
idaman bool        ida_export classname ## __beginning(const classname *, void*);                        \
idaman bool        ida_export classname ## __ending(const classname *, void*);                           \
idaman int         ida_export classname ## __generate(                                                  \
        const classname *,                                                                              \
        qstrvec_t*,                                                                                     \
        int*,                                                                               \
        color_t*,                                                                                       \
        bgcolor_t*,                                                                                     \
        void*,                                                                                          \
        int);                                                                               \
idaman void        ida_export classname ## __serialize(const classname *, bytevec_t *out);              \
idaman bool        ida_export classname ## __deserialize(classname *, const uchar **, const uchar *);   \
idaman int         ida_export classname ## __id(const classname *);                                     \
idaman const char *ida_export classname ## __name(const classname *);                                   \
idaman ea_t        ida_export classname ## __toea(const classname *);                                   \
idaman place_t *   ida_export classname ## __enter(const classname *, uint32 *);                        \
idaman void        ida_export classname ## __leave(const classname *, uint32);                          \
idaman bool        ida_export classname ## __rebase(classname *, const segm_move_infos_t &);


/// Helper to define virtual functions in ::place_t implementations
#define define_place_virtual_functions(class)                         \
  virtual void idaapi print(qstring *buf, void *ud) const override    \
        {        class ## __print(this, buf, ud); }                   \
  virtual uval_t idaapi touval(void *ud) const override               \
        { return class ## __touval(this, ud); }                        \
  virtual place_t *idaapi clone(void) const override                  \
        { return class ## __clone(this); }                            \
  virtual void idaapi copyfrom(const place_t *from) override          \
        {        class ## __copyfrom(this, from); }                    \
  virtual place_t *idaapi makeplace(                                  \
        void *ud,                                                     \
        uval_t x,                                                     \
        int _lnnum) const override                                    \
        { return class ## __makeplace(this,ud,x,_lnnum); }            \
  virtual int idaapi compare(const place_t *t2) const override        \
        { return class ## __compare(this, t2); }                      \
  virtual void idaapi adjust(void *ud) override                       \
        {        class ## __adjust(this,ud); }                        \
  virtual bool idaapi prev(void *ud) override                         \
        { return class ## __prev(this,ud); }                          \
  virtual bool idaapi next(void *ud) override                         \
        { return class ## __next(this,ud); }                          \
  virtual bool idaapi beginning(void *ud) const override              \
        { return class ## __beginning(this,ud); }                     \
  virtual bool idaapi ending(void *ud) const override                 \
        { return class ## __ending(this,ud); }                        \
  virtual int idaapi generate(                                        \
        qstrvec_t *_out,                                              \
        int *_out_lnnum,                                              \
        color_t *_out_pfx_color,                                      \
        bgcolor_t *_out_bg_color,                                     \
        void *_ud,                                                    \
        int _max) const override                                      \
  {                                                                   \
    return class ## __generate(                                       \
            this, _out, _out_lnnum, _out_pfx_color,                   \
            _out_bg_color, _ud, _max);                                \
  }                                                                   \
  virtual void idaapi serialize(bytevec_t *out) const override        \
       { class ## __serialize(this, out); }                           \
  virtual bool idaapi deserialize(                                    \
        const uchar **pptr,                                           \
        const uchar *end) override                                    \
       { return class ## __deserialize(this, pptr, end); }            \
  virtual int idaapi id() const override                              \
       { return class ## __id(this); }                                \
  virtual const char * idaapi name() const override                   \
       { return class ## __name(this); }                              \
  virtual ea_t idaapi toea() const override                           \
       { return class ## __toea(this); }                              \
  virtual place_t *idaapi enter(uint32 *out_flags) const override     \
       { return class ## __enter(this, out_flags); }                  \
  virtual void idaapi leave(uint32 flags) const override              \
       { return class ## __leave(this, flags); }                      \
  virtual bool idaapi rebase(const segm_move_infos_t &infos) override \
       { return class ## __rebase(this, infos); }                     \
  virtual int idaapi compare2(const place_t *t2, void *ud) const override \
  { return class ## __compare2(this, t2, ud); }

define_place_exported_functions(simpleline_place_t)


#endif // SWIG

//--------------------------------------------------------------------------

/*! \defgroup simpleline Simpleline interface

  \brief IDA custom viewer sample.

  It is enough to create an object of ::strvec_t class, put all lines
  into it and create a custom ida viewer (::ui_create_custom_viewer).
                                                                     \code
    strvec_t sv;
    // fill it with lines...
    simpleline_place_t s1;
    simpleline_place_t s2(sv.size()-1);
    cv = (TWidget *)callui(ui_create_custom_viewer,
                           "My title",
                           &s1,
                           &s2,
                           &s1,
                           0,
                           &sv).vptr;
                                                                     \endcode
  This will produce a nice colored text view.
  Also see the SDK's 'custview' and 'hexview' plugins for more complete examples.
*/
//@{

/// Maintain basic information for a line in a custom view
struct simpleline_t
{
  qstring line;       ///< line text
  color_t color;      ///< line prefix color
  bgcolor_t bgcolor;  ///< line background color
  simpleline_t(void) : color(1), bgcolor(DEFCOLOR) {}                                   ///< Constructor (default colors)
  simpleline_t(color_t c, const char *str) : line(str), color(c), bgcolor(DEFCOLOR) {}  ///< Constructor
  simpleline_t(const char *str) : line(str), color(1), bgcolor(DEFCOLOR) {}             ///< Constructor
  simpleline_t(const qstring &str) : line(str), color(1), bgcolor(DEFCOLOR) {}          ///< Constructor
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};

/// A collection of simple lines to populate a custom view.
/// This is an example of what you would pass as the 'ud' argument to create_custom_viewer()
typedef qvector<simpleline_t> strvec_t;

/// A location in a view populated by a ::strvec_t
class simpleline_place_t : public place_t
{
public:
  uint32 n; ///< line number
  simpleline_place_t(void) { n = 0; lnnum = 0; }    ///< Constructor
  simpleline_place_t(int _n) { n = _n; lnnum = 0; } ///< Constructor
  define_place_virtual_functions(simpleline_place_t);
};
//@}

//--------------------------------------------------------------------------
// user defined data for linearray_t: use ptr to result of calc_default_idaplace_flags()
#ifndef SWIG
define_place_exported_functions(idaplace_t)
#endif // SWIG
/// A location in a disassembly view
class idaplace_t : public place_t
{
public:
  ea_t ea; ///< address
  idaplace_t(void) {} ///< Constructor
  idaplace_t(ea_t x, int ln) : place_t(ln), ea(x) {} ///< Constructor
  define_place_virtual_functions(idaplace_t);
};

//--------------------------------------------------------------------------
// user defined data for linearray_t: nullptr
#ifndef SWIG
define_place_exported_functions(enumplace_t)
#endif // SWIG
/// A location in an enum view
class enumplace_t : public place_t
{
public:
  size_t idx;           ///< enum serial number
  bmask_t bmask;        ///< enum member bitmask
  uval_t value;         ///< enum member value
  uchar serial;         ///< enum member serial number
  enumplace_t(void) {}
  enumplace_t(size_t i, bmask_t m, uval_t v, uchar s, int ln)
    : place_t(ln), idx(i), bmask(m), value(v), serial(s) {}
  define_place_virtual_functions(enumplace_t);
};

//--------------------------------------------------------------------------
// user defined data for linearray_t: ea_t *pea
// if pea != nullptr then the function stack frame is displayed, *pea == function start
// else                normal structure list is displayed
#ifndef SWIG
define_place_exported_functions(structplace_t)
#endif // SWIG
/// A location in a struct view
class structplace_t : public place_t
{
public:
  uval_t idx;             ///< struct serial number
  uval_t offset;          ///< offset within struct
  structplace_t(void) {}  ///< Constructor
  structplace_t(uval_t i, uval_t o, int ln) : place_t(ln), idx(i), offset(o) {} ///< Constructor
  define_place_virtual_functions(structplace_t);
};

//-------------------------------------------------------------------------
/// A location in a hex view
#ifndef SWIG
define_place_exported_functions(hexplace_t)
struct outctx_base_t;
struct hexplace_gen_t;
class hexview_t;
idaman void ida_export hexplace_t__out_one_item(
        const hexplace_t *_this,
        outctx_base_t &ctx,
        const hexplace_gen_t *hg,
        int itemno,
        color_t *color,
        color_t patch_or_edit);
idaman size_t ida_export hexplace_t__ea2str(
        char *buf,
        size_t bufsize,
        const hexplace_gen_t *hg,
        ea_t ea);
#endif // SWIG

#define HEXPLACE_COLOR_EDITED     COLOR_SYMBOL
#define HEXPLACE_COLOR_PATCHED    COLOR_VOIDOP
#define HEXPLACE_COLOR_SHOWSPACES COLOR_RESERVED1

// A helper, used as 'userdata' for generating lines in a hexplace_t
// None of the function pointers can be nullptr
struct hexplace_gen_t
{
  // data format to display
  enum data_kind_t
  {
    dk_float,
    dk_int,
    dk_addr_names,
    dk_addr_text,
  };
  enum int_format_t
  {
    if_hex,
    if_signed,
    if_unsigned,
  };
  // result of get_byte_value()
  enum byte_kind_t
  {
    BK_VALID,        // has a valid value
    BK_INVALIDADDR,  // address is invalid
    BK_NOVALUE,      // address is valid but contains no value
  };

  virtual bool is_editing() const = 0;
  virtual bool is_editing_text() const = 0;
  virtual bool is_curitem_changed() const = 0;
  virtual bool is_edited_byte(ea_t ea, uint64 *out_value=nullptr) const = 0;
  virtual byte_kind_t get_byte_value(
        ea_t ea,
        uint64 *out_value,
        bool *out_edited) const = 0;
  virtual void get_encoding(qstring *out) const = 0;
  virtual ea_t get_cur_item_ea() const = 0;
  virtual void get_cur_item_text(qstring *out) const = 0;
  virtual int get_alignment() const = 0;
  virtual int get_line_len(ea_t ea) const = 0;
  virtual int get_items_per_line() const = 0;
  virtual int get_bytes_per_item() const = 0;
  virtual int get_item_width(ea_t ea) const = 0;
  virtual data_kind_t get_data_kind() const = 0;
  virtual int_format_t get_int_format() const = 0;
  virtual bool has_central_separator() const = 0;
  virtual bool show_text() const = 0;
  virtual bool show_segaddr() const = 0;
  virtual int get_bitness() const = 0;

  bool is_addr_kind() const
  {
    data_kind_t k = get_data_kind();
    return k == dk_addr_names || k == dk_addr_text;
  }
};

//-------------------------------------------------------------------------
// class to represent lines in a hex dump window
// one line consists of hv->grid.items_per_line items
// each item is hv->grid.bytes_per_item bytes for 8-bit bytes or one "wide" byte
class hexplace_t : public idaplace_t
{
protected:
  ea_t sol; // EA at start-of-line
public:
  hexplace_t(ea_t _ea, short ln) : idaplace_t(_ea, ln), sol(_ea) {}
  define_place_virtual_functions(hexplace_t);

  void out_one_item(
        outctx_base_t &ctx,
        const hexplace_gen_t *hg,
        int itemno,
        color_t *color,
        color_t patch_or_edit) const
  {
    hexplace_t__out_one_item(this, ctx, hg, itemno, color, patch_or_edit);
  }

  // convert ea to text
  // use seg:off if segment base is not zero
  // otherwise print just the address
  static size_t ea2str(char *buf, size_t bufsize, const hexplace_gen_t *hg, ea_t ea)
  {
    return hexplace_t__ea2str(buf, bufsize, hg, ea);
  }

};

//-------------------------------------------------------------------------
#define PCF_EA_CAPABLE          0x00000001 ///< toea() implementation returns meaningful data
#define PCF_MAKEPLACE_ALLOCATES 0x00000002 ///< makeplace() returns a freshly allocated (i.e., non-static)
                                           ///< instance. All new code should pass that flag to
                                           ///< register_place_class(), and the corresponding
                                           ///< makeplace() class implementation should
                                           ///< return new instances.

//-------------------------------------------------------------------------
idaman int ida_export internal_register_place_class(
        const place_t *tmplate,
        int flags,
        const plugin_t *owner,
        int sdk_version);


//-------------------------------------------------------------------------
/// Register information about a place_t class.
///
/// The kernel will not take ownership, nor delete the 'tmplate' instance.
/// Therefore, it's up to the plugin to handle it (the recommended way
/// of doing it is to pass address of a const static instance.)
/// In addition, the place_t will be automatically unregistered when the owner
/// plugin is unloaded from memory.
/// \param tmplate the place_t template
/// \param flags   or'ed combination of PCF_* flags. You should always
///                pass at least PCF_MAKEPLACE_ALLOCATES, and have the
///                place_t::makeplace() implementation create new instances.
/// \param owner   the owner plugin of the place_t type. Cannot be nullptr.
/// \return the place_t ID, or -1 if an error occurred.
inline int register_place_class(
        const place_t *tmplate,
        int flags,
        const plugin_t *owner)
{
  return internal_register_place_class(tmplate, flags, owner, IDA_SDK_VERSION);
}

//-------------------------------------------------------------------------
/// Get information about a previously-registered place_t class.
/// See also register_place_class().
/// \param out_flags       output flags (can be nullptr)
/// \param out_sdk_version sdk version the place was created with (can be nullptr)
/// \param id              place class ID
/// \return the place_t template, or nullptr if not found
idaman const place_t *ida_export get_place_class(
        int *out_flags,
        int *out_sdk_version,
        int id);

//-------------------------------------------------------------------------
/// See get_place_class()
inline const place_t *get_place_class_template(int id)
{
  return get_place_class(nullptr, nullptr, id);
}

//-------------------------------------------------------------------------
/// See get_place_class()
inline bool is_place_class_ea_capable(int id)
{
  int flags;
  if ( get_place_class(&flags, nullptr, id) == nullptr )
    return false;
  return (flags & PCF_EA_CAPABLE) != 0;
}

//-------------------------------------------------------------------------
/// Get the place class ID for the place that has been registered as 'name'.
/// \param name the class name
/// \return the place class ID, or -1 if not found
idaman int ida_export get_place_class_id(const char *name);

#ifndef __UI__
  // A TWidget represents any user-facing widget present in IDA.
  // E.g., "IDA View-*", "Hex View-*", "Imports", "General registers", ...
  class TWidget;
#else
  #ifdef __QT__
    namespace QT
    {
      class QWidget;
    };
    typedef QT::QWidget TWidget;
  #else
    class TView;
    typedef TView TWidget;
  #endif
#endif

//-------------------------------------------------------------------------
class sync_source_t
{
  uchar storage[16];

  const TWidget **get_widget_ptr_storage() const
  {
    return (const TWidget **) &storage[sizeof(storage) - sizeof(TWidget *)];
  }

public:
  sync_source_t(); // No
  sync_source_t(const TWidget *_view)
  {
    memset(storage, 0, sizeof(storage));
    *get_widget_ptr_storage() = _view;
    storage[0] = '\0';
  }
  sync_source_t(const char *_regname)
  {
    QASSERT(1716, _regname[0] != '\0');
    memset(storage, 0, sizeof(storage));
    qstrncpy((char *) storage, _regname, sizeof(storage));
  }

  bool operator==(const sync_source_t &_o) const
  {
    return memcmp(storage, _o.storage, sizeof(storage)) == 0;
  }
  bool operator!=(const sync_source_t &_o) const
  {
    return !((*this) == _o);
  }

  bool is_register() const { return storage[0] != '\0'; }
  bool is_widget() const { return !is_register(); }
  const TWidget *get_widget() const
  {
    QASSERT(1717, is_widget());
    return *get_widget_ptr_storage();
  }
  const char *get_register() const
  {
    QASSERT(1718, is_register());
    return (const char *) storage;
  }
};
DECLARE_TYPE_AS_MOVABLE(sync_source_t);
CASSERT(sizeof(sync_source_t) == 16);
typedef qvector<sync_source_t> sync_source_vec_t;

struct synced_group_t : public sync_source_vec_t
{
  bool has_widget(const TWidget *v) const { return has(sync_source_t((TWidget *) v)); }
  bool has_register(const char *r) const { return has(sync_source_t(r)); }
  bool has(const sync_source_t &ss) const { return find(ss) != end(); }
};

//-------------------------------------------------------------------------
/// Converts from an entry with a given place type, to another entry,
/// with another place type, to be used with the view 'view'. Typically
/// used when views are synchronized.
/// The 'renderer_info_t' part of 'dst' will be pre-filled with
/// the current renderer_info_t of 'view', while the 'place_t' instance
/// will always be nullptr.
enum lecvt_code_t
{
  LECVT_CANCELED = -1,
  LECVT_ERROR = 0,
  LECVT_OK = 1,
};

#define LECVT_WITHIN_LISTING 0x1 // only perform conversion if the location is contained in the current listing (e.g., in the decompiler, don't decompile other functions)
typedef lecvt_code_t idaapi lochist_entry_cvt2_t(
        lochist_entry_t *dst,
        const lochist_entry_t &src,
        TWidget *view,
        uint32 flags);

//-------------------------------------------------------------------------
/// Register a converter, that will be used for the following reasons:
/// - determine what view can be synchronized with what other view
/// - when views are synchronized, convert the location from one view,
///   into an appropriate location in the other view
/// - if one of p1 or p2 is "idaplace_t", and the other is PCF_EA_CAPABLE,
///   then the converter will also be called when the user wants to jump to
///   an address (e.g., by pressing "g"). In that case, from's place_t's lnnum
///   will be set to -1 (i.e., can be used to descriminate between proper
///   synchronizations, and jump to's if needed.)
///
/// Note: the converter can be used to convert in both directions, and can be
/// called with its 'from' being of the class of 'p1', or 'p2'.
/// If you want your converter to work in only one direction (e.g., from
/// 'my_dictionary_place_t' -> 'my_definition_place_t'), you can have it
/// return false when it is called with a lochist_entry_t's whose place is
/// of type 'my_definition_place_t'.
///
/// Note: Whenever one of the 'p1' or 'p2' places is unregistered,
/// corresponding converters will be automatically unregistered as well.
///
/// \param p1 the name of the first place_t class this converter can convert from/to
/// \param p2 the name of the second place_t class this converter can convert from/to
/// \param cvt the converter
idaman void ida_export register_loc_converter2(
        const char *p1,
        const char *p2,
        lochist_entry_cvt2_t *cvt);

//-------------------------------------------------------------------------
/// Search for a place converter from lochist_entry_t's with places of type
/// 'p1' to lochist_entry_t's with places of type 'p2'.
/// \param p1 the name of the place_t class to convert from
/// \param p2 the name of the place_t class to convert to
/// \return a converter, or nullptr if none found
idaman lochist_entry_cvt2_t *ida_export lookup_loc_converter2(
        const char *p1,
        const char *p2);



//----------------------------------------------------------------------
/// A position in a text window
class twinpos_t
{
public:
  place_t *at;                                    ///< location in view
  int x;                                          ///< cursor x
  twinpos_t(void)              { at=nullptr; x=0; }  ///< Constructor
  twinpos_t(place_t *t)        { at=t; x=0; }     ///< Constructor
  twinpos_t(place_t *t,int x0) { at=t; x=x0; }    ///< Constructor
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};

/// A line in a text window
class twinline_t
{
public:
  place_t *at;             ///< location in view
  qstring line;            ///< line contents
  color_t prefix_color;    ///< line prefix color
  bgcolor_t bg_color;      ///< line background color
  bool is_default;         ///< is this the default line of the current location?
  twinline_t(void)
  {
    at           = nullptr;
    prefix_color = 1;
    bg_color     = DEFCOLOR;
    is_default   = false;
  }
  twinline_t(place_t *t, color_t pc, bgcolor_t bc)
  {
    at           = t;
    prefix_color = pc;
    bg_color     = bc;
    is_default   = false;
  }
  DEFINE_MEMORY_ALLOCATION_FUNCS()
};
DECLARE_TYPE_AS_MOVABLE(twinline_t);

/// A group of lines in a text window
typedef qvector<twinline_t> text_t;

#ifndef SWIG

/// Helper for declaring member functions of the ::linearray_t class
#define DECLARE_LINEARRAY_HELPERS(decl) \
decl void  ida_export linearray_t_ctr(linearray_t *, void *ud); \
decl void  ida_export linearray_t_dtr(linearray_t *); \
decl int   ida_export linearray_t_set_place(linearray_t *, const place_t *new_at); \
decl bool  ida_export linearray_t_beginning(const linearray_t *); \
decl bool  ida_export linearray_t_ending(const linearray_t *); \
decl const qstring *ida_export linearray_t_down(linearray_t *); \
decl const qstring *ida_export linearray_t_up(linearray_t *);

class linearray_t;
DECLARE_LINEARRAY_HELPERS(idaman)
#else
#  define DECLARE_LINEARRAY_HELPERS(decl)
#endif // SWIG

/// The group of lines corresponding to a single place within a view
class linearray_t
{
  DECLARE_LINEARRAY_HELPERS(friend)
  int _set_place(const place_t *new_at);
  const qstring *_down     (void);
  const qstring *_up       (void);

  qstrvec_t lines;              // lines corresponding to the current place_t
  place_t *at;
  void *ud;                     // user defined data (UD)
                                // its meaning depends on the place_t used
  color_t prefix_color;         // prefix color
  bgcolor_t bg_color;           // background color
  qstring extra;                // the last line of the previous location after moving down
  int dlnnum;       // default line number (if unknown, -1)

  int   getlines(void);
  void  cleanup(void);

public:

  linearray_t(void *_ud)                     { linearray_t_ctr(this, _ud); } ///< Constructor
  ~linearray_t(void)                         { linearray_t_dtr(this); }      ///< Constructor
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  /// Position the array.
  /// This function must be called before calling any other member functions.
  ///
  /// ::linearray_t doesn't own ::place_t structures.
  /// The caller must take care of place_t objects.
  ///
  /// \param new_at  new position of the array
  /// \return the delta of lines that the linearray_t had to adjust the place by.             \n
  /// For example, if the place_t has a lnnum of 5, but it turns out, upon generating lines,  \n
  /// that the number of lines for that particular place is only 2, then 3 will be returned.
  int set_place(const place_t *new_at)      { return linearray_t_set_place(this, new_at); }

  /// Get the current place.
  /// If called before down(), then returns place of line which will be returned by down().
  /// If called after up(), then returns place if line returned by up().
  place_t *get_place    (void) const         { return at; }

  /// Get current background color.
  /// (the same behavior as with get_place(): good before down() and after up())
  bgcolor_t get_bg_color(void) const         { return bg_color; }

  /// Get current prefix color.
  /// (the same behavior as with get_place(): good before down() and after up())
  bgcolor_t get_pfx_color(void) const        { return prefix_color; }

  /// Get default line number.
  /// (the same behavior as with get_place(): good before down() and after up())
  int get_dlnnum(void) const                 { return dlnnum; }

  /// Get number of lines for the current place.
  /// (the same behavior as with get_place(): good before down() and after up())
  int get_linecnt(void) const                { return int(lines.size()); }

  /// Get pointer to user data
  void *userdata(void) const                 { return ud; }

  /// Change the user data
  void set_userdata(void *userd)             { ud = userd; }

  /// Are we at the beginning?
  bool beginning(void) const                 { return linearray_t_beginning(this); }

  // Are we at the end?
  bool ending(void) const                    { return linearray_t_ending(this); }

  /// Get a line from down direction.
  /// place is ok BEFORE
  const qstring *down(void)
        { return linearray_t_down(this); }

  /// Get a line from up direction.
  /// place is ok AFTER
  const qstring *up(void)
        { return linearray_t_up(this); }

};

//-------------------------------------------------------------------------
typedef qvector<const twinline_t*> section_lines_refs_t;
typedef qvector<section_lines_refs_t> sections_lines_refs_t;

//-------------------------------------------------------------------------
/// Contains information necessary for plugins to compute extra
/// information needed for rendering.
struct lines_rendering_input_t
{
  int cb;
  sections_lines_refs_t sections_lines; ///< references to the lines that are used for rendering
  const synced_group_t *sync_group;     ///< the 'synced' group 'widget' (see ui_get_lines_rendering_info) belongs to, or nullptr

  lines_rendering_input_t()
    : cb(sizeof(*this)),
      sync_group(nullptr) {}
};

//-------------------------------------------------------------------------
/// \defgroup CK_ keys
/// passed as 'bg_color' of a line_rendering_output_entry_t, to use
/// a CSS property of the widget ('qproperty-line-bgovl-extra-N')
/// instead of a direct color
//@{
//
#define CK_TRACE     80 ///< traced address
#define CK_TRACE_OVL 81 ///< overlay trace address
#define CK_EXTRA1    82 ///< extra background overlay #1
#define CK_EXTRA2    83 ///< extra background overlay #2
#define CK_EXTRA3    84 ///< extra background overlay #3
#define CK_EXTRA4    85 ///< extra background overlay #4
#define CK_EXTRA5    86 ///< extra background overlay #5
#define CK_EXTRA6    87 ///< extra background overlay #6
#define CK_EXTRA7    88 ///< extra background overlay #7
#define CK_EXTRA8    89 ///< extra background overlay #8
#define CK_EXTRA9    90 ///< extra background overlay #9
#define CK_EXTRA10   91 ///< extra background overlay #10
#define CK_EXTRA11   92 ///< extra background overlay #11
#define CK_EXTRA12   93 ///< extra background overlay #12
#define CK_EXTRA13   94 ///< extra background overlay #13
#define CK_EXTRA14   95 ///< extra background overlay #14
#define CK_EXTRA15   96 ///< extra background overlay #15
#define CK_EXTRA16   97 ///< extra background overlay #16

//@}

/// \defgroup LROEF_ line_rendering_output_entry_t flags
/// used by 'flags' of a line_rendering_output_entry_t
//@{
#define LROEF_MASK      0x00FFFFFF
#define LROEF_FULL_LINE 0x00000000    ///< full line background
#define LROEF_CPS_RANGE 0x00000001    ///< background for range of chars
//@}

struct line_rendering_output_entry_t
{
  const twinline_t *line;
  uint32 flags;           ///< \ref LROEF_

  // 0x00000000: nothing
  // 0xAABBGGRR: where AA is 0: BBGGRR contains a key (CK_*) to a color property
  // 0xAABBGGRR: where AA is !0: 0xAABBGGRR is the background color, with alpha value, to be applied to that line
  //
  // The 'bg_color' specified here, will be applied on top of the background
  // color that was computed for 'line', which itself can be:
  //   - none (i.e., the default background color),
  //   - a possible value stored in the IDB (see 'set_item_color()'),
  //   - a value provided by processor_t::ev_get_bg_color
  // The value provided here should typically be partly transparent
  // so that it doesn't obstruct the computed background color
  // (the best, by far, is to stick to CK_* keys: their corresponding
  // colors typically have partial translucency, and each theme can
  // customize them.)
  bgcolor_t bg_color;

  int cpx;                ///< number of char to start from, valid if LROEF_CPS_RANGE
  int nchars;             ///< chars count, valid if LROEF_CPS_RANGE

  line_rendering_output_entry_t(const twinline_t *_line, uint32 _flags=0, bgcolor_t _bg_color=0)
    : line(_line), flags(_flags), bg_color(_bg_color), cpx(-1), nchars(-1) {}

  line_rendering_output_entry_t(const twinline_t *_line, int _cpx, int _nchars, uint32 _flags, bgcolor_t _bg_color)
    : line(_line), flags(_flags|LROEF_CPS_RANGE), bg_color(_bg_color), cpx(_cpx), nchars(_nchars) {}

  bool is_bg_color_empty() const { return bg_color == 0; }
  bool is_bg_color_key() const { return (bg_color & 0xFF000000) == 0 && !is_bg_color_empty(); }
  bool is_bg_color_direct() const { return (bg_color & 0xFF000000) != 0; }

  bool operator==(const line_rendering_output_entry_t &r) const
  {
    bool ok = (flags & LROEF_MASK) == (r.flags & LROEF_MASK)
           && line == r.line
           && bg_color == r.bg_color;
    if ( ok && (flags & LROEF_CPS_RANGE) != 0 )
      ok = cpx == r.cpx && nchars == r.nchars;
    return ok;
  }

  bool operator!=(const line_rendering_output_entry_t &r) const
  { return !(*this == r); }
};
DECLARE_TYPE_AS_MOVABLE(line_rendering_output_entry_t);
typedef qvector<line_rendering_output_entry_t*> line_rendering_output_entries_refs_t;

//-------------------------------------------------------------------------
struct lines_rendering_output_t
{
  line_rendering_output_entries_refs_t entries;
  uint32 flags;

  lines_rendering_output_t() : flags(0) {}
  ~lines_rendering_output_t()
  {
    clear();
  }

  void clear()
  {
    for ( size_t i = 0, n = entries.size(); i < n; ++i )
      delete entries[i];
  }

  bool operator==(const lines_rendering_output_t &r) const
  {
    if ( flags != r.flags )
      return false;
    const size_t n = entries.size();
    if ( n != r.entries.size() )
      return false;
    for ( size_t i = 0; i < n; ++i )
      if ( *entries[i] != *r.entries[i] )
        return false;
    return true;
  }

  bool operator!=(const lines_rendering_output_t &r) const
  { return !(*this == r); }

  void swap(lines_rendering_output_t &r)
  {
    qswap(flags, r.flags);
    entries.swap(r.entries);
  }
};


#ifndef SWIG
/// Bitmask of builtin window types to be refreshed:
idaman uint64 ida_export get_dirty_infos(void);
#endif // SWIG


/// Request a refresh of a builtin window.
/// \param mask  \ref IWID_
/// \param cnd   set if true or clear flag otherwise

idaman void ida_export request_refresh(uint64 mask, bool cnd=true);
inline void clear_refresh_request(uint64 mask) { request_refresh(mask, false); }


/// Get a refresh request state
/// \param mask  \ref IWID_
/// \returns the state (set or cleared)

idaman bool ida_export is_refresh_requested(uint64 mask);


//-------------------------------------------------------------------------
typedef int twidget_type_t; ///< \ref BWN_

/// \defgroup BWN_ Window types
/// also see \ref ui_open_builtin_funcs
//@{
#define BWN_UNKNOWN       -1 ///< unknown window
#define BWN_EXPORTS        0 ///< exports
#define BWN_IMPORTS        1 ///< imports
#define BWN_NAMES          2 ///< names
#define BWN_FUNCS          3 ///< functions
#define BWN_STRINGS        4 ///< strings
#define BWN_SEGS           5 ///< segments
#define BWN_SEGREGS        6 ///< segment registers
#define BWN_SELS           7 ///< selectors
#define BWN_SIGNS          8 ///< signatures
#define BWN_TILS           9 ///< type libraries
#define BWN_LOCTYPS       10 ///< local types
#define BWN_CALLS         11 ///< function calls
#define BWN_PROBS         12 ///< problems
#define BWN_BPTS          13 ///< breakpoints
#define BWN_THREADS       14 ///< threads
#define BWN_MODULES       15 ///< modules
#define BWN_TRACE         16 ///< tracing view
#define BWN_CALL_STACK    17 ///< call stack
#define BWN_XREFS         18 ///< xrefs
#define BWN_SEARCH        19 ///< search results
#define BWN_FRAME         25 ///< function frame
#define BWN_NAVBAND       26 ///< navigation band
#define BWN_ENUMS         27 ///< enumerations
#define BWN_STRUCTS       28 ///< structures
#define BWN_DISASM        29 ///< disassembly views
#define BWN_DUMP          30 ///< hex dumps
#define BWN_NOTEPAD       31 ///< notepad
#define BWN_OUTPUT        32 ///< the text area, in the output window
#define BWN_CLI           33 ///< the command-line, in the output window
#define BWN_WATCH         34 ///< the 'watches' debugger window
#define BWN_LOCALS        35 ///< the 'locals' debugger window
#define BWN_STKVIEW       36 ///< the 'Stack view' debugger window
#define BWN_CHOOSER       37 ///< a non-builtin chooser
#define BWN_SHORTCUTCSR   38 ///< the shortcuts chooser (Qt version only)
#define BWN_SHORTCUTWIN   39 ///< the shortcuts window (Qt version only)
#define BWN_CPUREGS       40 ///< one of the 'General registers', 'FPU register', ... debugger windows
#define BWN_SO_STRUCTS    41 ///< the 'Structure offsets' dialog's 'Structures and Unions' panel
#define BWN_SO_OFFSETS    42 ///< the 'Structure offsets' dialog's offset panel
#define BWN_CMDPALCSR     43 ///< the command palette chooser (Qt version only)
#define BWN_CMDPALWIN     44 ///< the command palette window (Qt version only)
#define BWN_SNIPPETS      45 ///< the 'Execute script' window
#define BWN_CUSTVIEW      46 ///< custom viewers
#define BWN_ADDRWATCH     47 ///< the 'Watch List' window
#define BWN_PSEUDOCODE    48 ///< hexrays decompiler views
#define BWN_CALLS_CALLERS 49 ///< function calls, callers
#define BWN_CALLS_CALLEES 50 ///< function calls, callees
#define BWN_MDVIEWCSR     51 ///< lumina metadata view chooser
#define BWN_DISASM_ARROWS 52 ///< disassembly arrows widget
#define BWN_CV_LINE_INFOS 53 ///< custom viewers' lineinfo widget
#define BWN_SRCPTHMAP_CSR 54 ///< "Source paths..."'s path mappings chooser
#define BWN_SRCPTHUND_CSR 55 ///< "Source paths..."'s undesired paths chooser
#define BWN_UNDOHIST      56 ///< Undo history
#define BWN_SNIPPETS_CSR  57 ///< the list of snippets in the 'Execute script' window
#define BWN_SCRIPTS_CSR   58 ///< the "Recent scripts" chooser
#define BWN_BOOKMARKS     59 ///< a persistent 'Bookmarks' widget

/// Alias. Some BWN_* were confusing, and thus have been renamed.
/// This is to ensure bw-compat.
#define BWN_STACK   BWN_CALL_STACK
#define BWN_DISASMS BWN_DISASM  ///< \copydoc BWN_STACK
#define BWN_DUMPS   BWN_DUMP    ///< \copydoc BWN_STACK
#define BWN_SEARCHS BWN_SEARCH  ///< \copydoc BWN_STACK
//@}

/// \defgroup IWID_ Window refresh flags
/// passed as 'mask' parameter to request_refresh()
//@{
#define IWID_EXPORTS       (1ULL << BWN_EXPORTS      ) ///< exports           (0)
#define IWID_IMPORTS       (1ULL << BWN_IMPORTS      ) ///< imports           (1)
#define IWID_NAMES         (1ULL << BWN_NAMES        ) ///< names             (2)
#define IWID_FUNCS         (1ULL << BWN_FUNCS        ) ///< functions         (3)
#define IWID_STRINGS       (1ULL << BWN_STRINGS      ) ///< strings           (4)
#define IWID_SEGS          (1ULL << BWN_SEGS         ) ///< segments          (5)
#define IWID_SEGREGS       (1ULL << BWN_SEGREGS      ) ///< segment registers (6)
#define IWID_SELS          (1ULL << BWN_SELS         ) ///< selectors         (7)
#define IWID_SIGNS         (1ULL << BWN_SIGNS        ) ///< signatures        (8)
#define IWID_TILS          (1ULL << BWN_TILS         ) ///< type libraries    (9)
#define IWID_LOCTYPS       (1ULL << BWN_LOCTYPS      ) ///< local types       (10)
#define IWID_CALLS         (1ULL << BWN_CALLS        ) ///< function calls    (11)
#define IWID_PROBS         (1ULL << BWN_PROBS        ) ///< problems          (12)
#define IWID_BPTS          (1ULL << BWN_BPTS         ) ///< breakpoints       (13)
#define IWID_THREADS       (1ULL << BWN_THREADS      ) ///< threads           (14)
#define IWID_MODULES       (1ULL << BWN_MODULES      ) ///< modules           (15)
#define IWID_TRACE         (1ULL << BWN_TRACE        ) ///< tracing view      (16)
#define IWID_CALL_STACK    (1ULL << BWN_CALL_STACK   ) ///< call stack        (17)
#define IWID_XREFS         (1ULL << BWN_XREFS        ) ///< xrefs             (18)
#define IWID_SEARCH        (1ULL << BWN_SEARCH       ) ///< search results    (19)
#define IWID_FRAME         (1ULL << BWN_FRAME        ) ///< function frame    (25)
#define IWID_NAVBAND       (1ULL << BWN_NAVBAND      ) ///< navigation band   (26)
#define IWID_ENUMS         (1ULL << BWN_ENUMS        ) ///< enumerations      (27)
#define IWID_STRUCTS       (1ULL << BWN_STRUCTS      ) ///< structures        (28)
#define IWID_DISASM        (1ULL << BWN_DISASM       ) ///< disassembly views (29)
#define IWID_DUMP          (1ULL << BWN_DUMP         ) ///< hex dumps         (30)
#define IWID_NOTEPAD       (1ULL << BWN_NOTEPAD      ) ///< notepad           (31)
#define IWID_OUTPUT        (1ULL << BWN_OUTPUT       ) ///< output            (32)
#define IWID_CLI           (1ULL << BWN_CLI          ) ///< input line        (33)
#define IWID_WATCH         (1ULL << BWN_WATCH        ) ///< watches           (34)
#define IWID_LOCALS        (1ULL << BWN_LOCALS       ) ///< locals            (35)
#define IWID_STKVIEW       (1ULL << BWN_STKVIEW      ) ///< stack view        (36)
#define IWID_CHOOSER       (1ULL << BWN_CHOOSER      ) ///< chooser           (37)
#define IWID_SHORTCUTCSR   (1ULL << BWN_SHORTCUTCSR  ) ///< shortcuts chooser (38)
#define IWID_SHORTCUTWIN   (1ULL << BWN_SHORTCUTWIN  ) ///< shortcuts window  (39)
#define IWID_CPUREGS       (1ULL << BWN_CPUREGS      ) ///< registers         (40)
#define IWID_SO_STRUCTS    (1ULL << BWN_SO_STRUCTS   ) ///< stroff            (41)
#define IWID_SO_OFFSETS    (1ULL << BWN_SO_OFFSETS   ) ///< stroff            (42)
#define IWID_CMDPALCSR     (1ULL << BWN_CMDPALCSR    ) ///< command palette   (43)
#define IWID_CMDPALWIN     (1ULL << BWN_CMDPALWIN    ) ///< command palette   (44)
#define IWID_SNIPPETS      (1ULL << BWN_SNIPPETS     ) ///< snippets          (45)
#define IWID_CUSTVIEW      (1ULL << BWN_CUSTVIEW     ) ///< custom viewers    (46)
#define IWID_ADDRWATCH     (1ULL << BWN_ADDRWATCH    ) ///< address watches   (47)
#define IWID_PSEUDOCODE    (1ULL << BWN_PSEUDOCODE   ) ///< decompiler        (48)
#define IWID_CALLS_CALLERS (1ULL << BWN_CALLS_CALLERS) ///< funcalls, callers (49)
#define IWID_CALLS_CALLEES (1ULL << BWN_CALLS_CALLEES) ///< funcalls, callees (50)
#define IWID_MDVIEWCSR     (1ULL << BWN_MDVIEWCSR    ) ///< lumina md view    (51)
#define IWID_DISASM_ARROWS (1ULL << BWN_DISASM_ARROWS) ///< arrows widget     (52)
#define IWID_CV_LINE_INFOS (1ULL << BWN_CV_LINE_INFOS) ///< lineinfo widget   (53)
#define IWID_SRCPTHMAP_CSR (1ULL << BWN_SRCPTHMAP_CSR) ///< mappings chooser  (54)
#define IWID_SRCPTHUND_CSR (1ULL << BWN_SRCPTHUND_CSR) ///< undesired chooser (55)
#define IWID_UNDOHIST      (1ULL << BWN_UNDOHIST     ) ///< Undo history      (56)
#define IWID_SNIPPETS_CSR  (1ULL << BWN_SNIPPETS_CSR ) ///< snippets chooser  (57)
#define IWID_SCRIPTS_CSR   (1ULL << BWN_SCRIPTS_CSR  ) ///< recent scripts    (58)
#define IWID_BOOKMARKS     (1ULL << BWN_BOOKMARKS)     ///< bookmarks list    (59)

#define IWID_IDAMEMOS      (IWID_DISASMS|IWID_DUMPS  ) ///< disassembly + hex dump views
#define IWID_ALL           0xFFFFFFFFFFFFFFFFULL       ///< mask

/// Alias. Some IWID_* were confusing, and thus have been renamed.
/// This is to ensure bw-compat.
#define IWID_STACK   IWID_CALL_STACK
#define IWID_DISASMS IWID_DISASM
#define IWID_DUMPS   IWID_DUMP
#define IWID_SEARCHS IWID_SEARCH
//@}

/// Does the given widget type specify a chooser widget?

inline bool is_chooser_widget(twidget_type_t t)
{
  return t == BWN_CHOOSER
      || (t >= BWN_EXPORTS && t <= BWN_SEARCH && t != BWN_CALLS)
      || t == BWN_SHORTCUTCSR
      || t == BWN_CMDPALCSR
      || t == BWN_CALLS_CALLERS
      || t == BWN_CALLS_CALLEES
      || t == BWN_MDVIEWCSR
      || t == BWN_SRCPTHMAP_CSR
      || t == BWN_SRCPTHUND_CSR
      || t == BWN_UNDOHIST
      || t == BWN_SNIPPETS_CSR
      || t == BWN_SCRIPTS_CSR
      || t == BWN_BOOKMARKS;
}


//---------------------------------------------------------------------------
//      D E B U G G I N G   F U N C T I O N S
//---------------------------------------------------------------------------

/// Controls debug messages - combination of \ref IDA_DEBUG_
idaman uint32 ida_export_data debug;

/// \defgroup IDA_DEBUG_ IDA debug bits
/// used by ::debug
//@{
#define IDA_DEBUG_DREFS         0x00000001      ///< drefs
#define IDA_DEBUG_OFFSET        0x00000002      ///< offsets
#define IDA_DEBUG_FLIRT         0x00000004      ///< flirt
#define IDA_DEBUG_IDP           0x00000008      ///< idp module
#define IDA_DEBUG_LDR           0x00000010      ///< ldr module
#define IDA_DEBUG_PLUGIN        0x00000020      ///< plugin module
#define IDA_DEBUG_IDS           0x00000040      ///< ids files
#define IDA_DEBUG_CONFIG        0x00000080      ///< config file
#define IDA_DEBUG_CHECKMEM      0x00000100      ///< check heap consistency
#define IDA_DEBUG_LICENSE       0x00000200      ///< licensing
#define IDA_DEBUG_DEMANGLE      0x00000400      ///< demangler
#define IDA_DEBUG_QUEUE         0x00000800      ///< queue
#define IDA_DEBUG_ROLLBACK      0x00001000      ///< rollback
#define IDA_DEBUG_ALREADY       0x00002000      ///< already data or code
#define IDA_DEBUG_TIL           0x00004000      ///< type system
#define IDA_DEBUG_NOTIFY        0x00008000      ///< show all notifications
#define IDA_DEBUG_DEBUGGER      0x00010000      ///< debugger
#define IDA_DEBUG_APPCALL       0x00020000      ///< appcall
#define IDA_DEBUG_SRCDBG        0x00040000      ///< source debugging
#define IDA_DEBUG_ACCESSIBILITY 0x00080000      ///< accessibility
#define IDA_DEBUG_NETWORK       0x00100000      ///< network
#define IDA_DEBUG_INTERNET      IDA_DEBUG_NETWORK ///< internet connection (for API backward compatibility)
#define IDA_DEBUG_SIMPLEX       0x00200000      ///< full stack analysis
#define IDA_DEBUG_DBGINFO       0x00400000      ///< handling of debug info (e.g. pdb, dwarf)
#define IDA_DEBUG_LUMINA        0x00800000      ///< lumina related
#define IDA_DEBUG_THEMES        0x01000000      ///< themes
#define IDA_DEBUG_REGEX         0x02000000      ///< regular expression
#define IDA_DEBUG_SUBPROC       0x04000000      ///< sub process
#define IDA_DEBUG_ALWAYS        0xFFFFFFFF      ///< everything
//@}

#ifndef SWIG

/// Display debug message.
/// \param ida_debug_bits  \ref IDA_DEBUG_, also see ::debug
/// \param format           printf()-style format
/// \return number of bytes output
/// Note: use deb() macro

AS_PRINTF(1, 2) inline int ida_deb(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int nbytes = callui(ui_msg, format, va).i;
  va_end(va);
  return nbytes;
}

#define deb(ida_debug_bits, ...)           \
  do                                       \
  {                                        \
    if ( (debug & (ida_debug_bits)) != 0 ) \
      ida_deb(__VA_ARGS__);                \
  } while ( false )

/// Display hex dump in the messages window

AS_PRINTF(3, 4) inline void show_hex(
        const void *dataptr,
        size_t len,
        const char *format,
        ...)
{
  va_list va;
  va_start(va,format);
  vshow_hex(dataptr, len, format, va);
  va_end(va);
}


/// Display hex dump of a file in the messages window

AS_PRINTF(4, 5) inline void show_hex_file(
        linput_t *li,
        int64 pos,
        size_t count,
        const char *format,
        ...)
{
  va_list va;
  va_start(va,format);
  vshow_hex_file(li, pos, count, format, va);
  va_end(va);
}
#endif // SWIG

//-------------------------------------------------------------------------
//      U I   S E R V I C E  F U N C T I O N S
//-------------------------------------------------------------------------

/// Action states - returned by action_handler_t::update()
enum action_state_t
{
  AST_ENABLE_ALWAYS,      ///< enable action and do not call action_handler_t::update() anymore

  AST_ENABLE_FOR_IDB,     ///< enable action for the current idb.
                          ///< call action_handler_t::update() when a database is opened/closed

  AST_ENABLE_FOR_WIDGET,  ///< enable action for the current widget.
                          ///< call action_handler_t::update() when a widget gets/loses focus

  AST_ENABLE,             ///< enable action - call action_handler_t::update() when anything changes

  AST_DISABLE_ALWAYS,     ///< disable action and do not call action_handler_t::action() anymore
  AST_DISABLE_FOR_IDB,    ///< analog of ::AST_ENABLE_FOR_IDB
  AST_DISABLE_FOR_WIDGET, ///< analog of ::AST_ENABLE_FOR_WIDGET
  AST_DISABLE,            ///< analog of ::AST_ENABLE
};


/// Check if the given action state is one of AST_ENABLE*

inline bool is_action_enabled(action_state_t s)
{
  return s <= AST_ENABLE;
}

//-------------------------------------------------------------------------
/// \defgroup CH_ Generic chooser flags
/// used as 'chooser_base_t::flags'
//@{
/// Modal chooser
#define CH_MODAL          0x00000001
/// The chooser instance's lifecycle is not tied to the lifecycle of the
/// widget showing its contents. Closing the widget will not destroy the
/// chooser structure. This allows for, e.g., static global chooser instances
/// that don't need to be allocated on the heap. Also stack-allocated chooser
/// instances must set this bit.
#define CH_KEEP           0x00000002
/// The chooser will allow multi-selection (only for GUI choosers). This bit
/// is set when using the chooser_multi_t structure.
#define CH_MULTI          0x00000004
/// Obsolete
#define CH_MULTI_EDIT     0x00000008
/// do not display ok/cancel/help/search buttons.
/// Meaningful only for gui modal windows because non-modal windows do not
/// have any buttons anyway. Text mode does not have them neither.
#define CH_NOBTNS         0x00000010
/// generate ui_get_chooser_item_attrs (gui only)
#define CH_ATTRS          0x00000020
#define CH_UNUSED         0x00000040
/// if a non-modal chooser was already open, change selection to the default
/// one
#define CH_FORCE_DEFAULT  0x00000080
/// allow to insert new items
#define CH_CAN_INS        0x00000100
/// allow to delete existing item(s)
#define CH_CAN_DEL        0x00000200
/// allow to edit existing item(s)
#define CH_CAN_EDIT       0x00000400
/// allow to refresh chooser
#define CH_CAN_REFRESH    0x00000800

/// open with quick filter enabled and focused
#define CH_QFLT           0x00001000
#define CH_QFTYP_SHIFT       13
#define CH_QFTYP_DEFAULT     0  ///< set quick filtering type to the possible existing default for this chooser
#define CH_QFTYP_NORMAL      (1 << CH_QFTYP_SHIFT) ///< normal (i.e., lexicographical) quick filter type
#define CH_QFTYP_WHOLE_WORDS (2 << CH_QFTYP_SHIFT) ///< whole words quick filter type
#define CH_QFTYP_REGEX       (3 << CH_QFTYP_SHIFT) ///< regex quick filter type
#define CH_QFTYP_FUZZY       (4 << CH_QFTYP_SHIFT) ///< fuzzy search quick filter type
#define CH_QFTYP_MASK        (0x7 << CH_QFTYP_SHIFT)

/// don't show a status bar
#define CH_NO_STATUS_BAR  0x00010000

/// restore floating position if present (equivalent of WOPN_RESTORE) (GUI version only)
#define CH_RESTORE        0x00020000

/// triggering a 'edit/rename' (i.e., F2 shortcut) on a cell,
/// should call the edit() callback for the corresponding row.
#define CH_RENAME_IS_EDIT 0x00040000

#define CH_BUILTIN_SHIFT 19
#define CH_BUILTIN(id)   ((id+1) << CH_BUILTIN_SHIFT)
/// Mask for builtin chooser numbers. Plugins should not use them.
#define CH_BUILTIN_MASK  (0x3F << CH_BUILTIN_SHIFT)

/// The chooser can provide a dirtree_t, meaning a tree-like structure
/// can be provided to the user (instead of a flat table)
#define CH_HAS_DIRTREE     0x02000000

#define CH_TM_NO_TREE      0x00000000 ///< chooser will show up in no-tree mode
#define CH_TM_FOLDERS_ONLY 0x04000000 ///< chooser will show in folders-only mode
#define CH_TM_FULL_TREE    0x08000000 ///< chooser will show in no-tree mode
#define CH_TM_SHIFT        26
#define CH_TM_MASK         (0x3 << CH_TM_SHIFT)

/// The chooser can be used in a diffing/merging workflow
#define CH_HAS_DIFF        0x10000000

/// The chooser will not have sorting abilities
#define CH_NO_SORT         0x20000000

/// The chooser will not have filtering abilities
#define CH_NO_FILTER       0x40000000

/// the chooser tree is not persisted (it is not loaded on startup and is
/// not saved on exit)
#define CH_NON_PERSISTED_TREE 0x80000000
//@}

/// \defgroup CH2_ Extended chooser flags
/// used as 'chooser_base_t::flags2'
//@{
/// The chooser is lazy-loaded; it receives the callback do_lazy_load_dir()
/// (only meaningful when CH_HAS_DIRTREE is set)
#define CH2_LAZY_LOADED 0x0001
//@}

/// \defgroup CHCOL_ Chooser column flags
/// used by 'widths' parameter for \ref choosers
//@{
#define CHCOL_PLAIN     0x00000000  ///< plain string
#define CHCOL_PATH      0x00010000  ///< file path. TUI IDA will truncate
                                    ///< excessive cell lengths starting at
                                    ///< their beginning, and prepending the
                                    ///< resulting text with "..." order to
                                    ///< leave the filename visible
#define CHCOL_HEX       0x00020000  ///< hexadecimal number
#define CHCOL_DEC       0x00030000  ///< decimal number
#define CHCOL_EA        0x00040000  ///< address
#define CHCOL_FNAME     0x00050000  ///< function name. If a chooser column has
                                    ///< this flag set and implements
                                    ///< chooser_base_t::get_ea(), rows background
                                    ///< colors will be automatically set to
                                    ///< match the navigator's "Library function",
                                    ///< "Lumina function" and
                                    ///< "External symbol" colors
#define CHCOL_FORMAT    0x00070000  ///< column format mask

#define CHCOL_DEFHIDDEN 0x00100000  ///< column should be hidden by default
#define CHCOL_DRAGHINT  0x00200000  ///< the column number that will be used
                                    ///< to build hints for the dragging undo
                                    ///< label. This should be provided for at
                                    ///< most one column for any given chooser.
#define CHCOL_INODENAME 0x00400000  ///< if CH_HAS_DIRTREE has been specified,
                                    ///< this instructs the chooser that this
                                    ///< column shows the inode name. This
                                    ///< should be provided for at most one
                                    ///< column for any given chooser.
//@}


/// \defgroup CHITEM_ Chooser item property bits
/// used by chooser_item_attrs_t::flags
//@{
#define CHITEM_BOLD   0x0001 ///< display the item in bold
#define CHITEM_ITALIC 0x0002 ///< display the item in italic
#define CHITEM_UNDER  0x0004 ///< underline the item
#define CHITEM_STRIKE 0x0008 ///< strikeout the item
#define CHITEM_GRAY   0x0010 ///< gray out the item
//@}

/// \name Chooser title
/// prefixes to be used in the chooser title
//@{
#define CHOOSER_NOMAINMENU  "NOMAINMENU\n"   ///< do not display main menu
#define CHOOSER_NOSTATUSBAR "NOSTATUSBAR\n"  ///< do not display status bar (obsolete. Use CH_NO_STATUS_BAR instead)
//@}

class dirtree_t;

/// Chooser item attributes
struct chooser_item_attrs_t
{
  int cb;               ///< size of this structure.
                        ///< the callback must check this field and fill only
                        ///< the existing fields. the first 2 fields always exist:
  int flags;            ///< \ref CHITEM_
  bgcolor_t color;      ///< item color
  chooser_item_attrs_t()
    : cb(sizeof(chooser_item_attrs_t)),
      flags(0),
      color(DEFCOLOR) {}
  void reset(void)      ///< restore to defaults
  {
    cb    = sizeof(chooser_item_attrs_t);
    flags = 0;
    color = DEFCOLOR;
  }
};

/// the standard action description
/// The chooser has 4 standard actions: Insert, Delete, Edit, Refresh.
/// We used the term "popup actions" before, but now we prefer "standard
/// actions", so there is some confusion in the naming.
struct action_ctx_base_t;
typedef action_ctx_base_t action_update_ctx_t;
struct chooser_stdact_desc_t
{
  int version = 1;      ///< to support the backward compatibility
  const char *label;    ///< see action_desc_t
  const char *tooltip;
  int icon;

  chooser_stdact_desc_t(
        const char *_label = nullptr,
        const char *_tooltip = nullptr,
        int _icon = -1)
    : label(_label), tooltip(_tooltip), icon(_icon) {}
  virtual ~chooser_stdact_desc_t() {}

  /// the update callback, see action_handler_t::update()
  /// When the update callback is called from the chooser UI engine, it can
  /// be sure that ctx.source.chooser is a valid pointer to chooser_base_t
  /// and that there are selected items for the Delete and Edit actions.
  virtual action_state_t idaapi ucb(action_update_ctx_t * /*ctx*/)
  {
    return AST_ENABLE_FOR_WIDGET;
  }
};

/// Chooser object. #chooser
struct chooser_base_t
{
#ifdef SWIG
  %immutable;
#endif
protected:
  uint8 version = 3;  ///< version of the class
  uint8 reserved = 0;
  uint16 flags2;      ///< \ref CH2_
  uint32 flags;       ///< \ref CH_

public:
  // TODO reduce to 4 values
  // embedded chooser: width, height. Other values are ignored.
  // qt: y1 == -2 => minimal height (and centered)
  //     Other values are ignored.
  int x0 = -1;        ///< screen position, \ref choosers
  int y0 = -1;
  int x1 = -1;
  int y1 = -1;
  int width = 0;      ///< (in chars)
  int height = 0;     ///< (in chars)

  const char *title;  ///< menu title (includes ptr to help).
                      ///< May have chooser title prefixes (see "Chooser
                      ///< title" above).
  int columns;        ///< number of columns
  const int *widths;  ///< column widths
                      ///<   - low 16 bits of each value hold the column width
                      ///<   - high 16 bits are flags (see \ref CHCOL_)
  const char *const *header;
                      ///< header line; contains the tooltips, and column name
                      ///< for each of 'columns' columns.
                      ///< When tooltips need to be provided, the syntax
                      ///< should be: "#tooltip#column-name". (Otherwise,
                      ///< the syntax is simply "column-name".)
  int icon = -1;      ///< default icon

  /// \defgroup chooser_index Special values of the chooser index
  /// Used in the following contexts:
  ///   1. as the return value of the choose() function
  ///   2. as the `idx` field of the return value of the get_item_index(),
  ///      ins(), del(), edit(), enter(), refresh() callbacks of the
  ///      `chooser_t` structure
  ///   3. as the parameter `n` of the chooser_t::refresh() callback
  /// Usage matrix
  //  Context        | 1 | 2 | 3
  //  ---------------------------
  //  NO_SELECTION   | X | X | X
  //  EMPTY_CHOOSER  | X |   |
  //  ALREADY_EXISTS | X |   |
  //@{
  static constexpr ssize_t NO_SELECTION   = -1; ///< there is no selected item
  static constexpr ssize_t EMPTY_CHOOSER  = -2; ///< the chooser has no data
                                                ///< and cannot be displayed
  static constexpr ssize_t ALREADY_EXISTS = -3; ///< the non-modal chooser
                                                ///< with the same data is
                                                ///< already open
  static constexpr ssize_t NO_ATTR        = -4; ///< reserved for IDAPython
  //@}

  enum { POPUP_INS, POPUP_DEL, POPUP_EDIT, POPUP_REFRESH, NSTDPOPUPS };
  /// array of custom labels of the standard actions.
  /// Used to replace labels for these actions. \n
  /// An empty name means that the default name will be used.
  /// \note Availability of these actions is determined by the CH_CAN_...
  /// flags.
  /// The label, icon and other action attributes can be overwritten in the
  /// action description returned by get_stdact_descs()
  qstring popup_names[NSTDPOPUPS];

  int deflt_col = 0;  ///< Column that will have focus.

  chooser_base_t(
          uint32 flags_ = 0,
          int columns_ = 0,
          const int *widths_ = nullptr,
          const char *const *header_ = nullptr,
          const char *title_ = nullptr,
          uint16 flags2_ = 0)
    : flags2(flags2_),
      flags(flags_),
      title(title_),
      columns(columns_),
      widths(widths_),
      header(header_) {}
  virtual ~chooser_base_t() {}
  DEFINE_MEMORY_ALLOCATION_FUNCS()

  // called when the corresponding widget is destroyed.
  //
  // In some rare cases where multiple chooser_base_t instance can
  // be backed by the same data (\sa get_obj_id), and a second instance
  // is created while the first is already displayed (therefore making
  // that second instance a duplicate), the second instance will be
  // destroyed through this method (and chooser_base_t::ALREADY_EXISTS
  // will be returned from choose().)
  void call_destructor()
  {
    if ( (flags & CH_KEEP) == 0 )
      delete this;
  }

  /// get pointer to some custom data.
  /// \note These data are also called "the underlying object".
  /// Now this method is used only in the ActionsInspector class and
  /// ida_kernwin.Choose IDAPython's class.
  virtual void *get_chooser_obj() { return this; }

  /// get the id of the chooser data.
  /// The choosers are the same if they have the same data ids.
  /// \param[out] len  length of the id. If it is 0 then it is considered
  ///                  that the method returned an unique id.
  /// \return  address of the id or nullptr in the case len == 0
  virtual const void *get_obj_id(size_t *len) const
  {
    // return the unique id
    *len = 0;
    return nullptr;
  }

  /// do the current and the given objects hold the same data?
  bool is_same(const chooser_base_t *other) const
  {
    size_t len1;
    const void *id1 = get_obj_id(&len1);
    size_t len2;
    const void *id2 = other->get_obj_id(&len2);
    return len1 == len2 && len1 != 0 && memcmp(id1, id2, len1) == 0;
  }

  /// is an operation allowed?
  bool can_ins() const     { return (flags & CH_CAN_INS    ) != 0; }
  bool can_del() const     { return (flags & CH_CAN_DEL    ) != 0; }
  bool can_edit() const    { return (flags & CH_CAN_EDIT   ) != 0; }
  bool can_refresh() const { return (flags & CH_CAN_REFRESH) != 0; }

  /// is a standard action allowed?
  bool popup_allowed(int stdact_idx) const
  {
    switch ( stdact_idx )
    {
      case POPUP_INS:     return can_ins();
      case POPUP_DEL:     return can_del();
      case POPUP_EDIT:    return can_edit();
      case POPUP_REFRESH: return can_refresh();
      default:            return false;
    }
  }
  bool is_status_bar_hidden() const { return (flags & CH_NO_STATUS_BAR) != 0; }
  bool should_restore_geometry() const { return (flags & CH_RESTORE) != 0; }
  /// is choose modal?
  bool is_modal()         const { return (flags & CH_MODAL) != 0; }
  /// is multi-selection allowed?
  bool is_multi()         const { return (flags & CH_MULTI) != 0; }
  /// should chooser generate ui_get_chooser_item_attrs events?
  bool ask_item_attrs()   const { return (flags & CH_ATTRS) != 0; }
  /// should selection of the already opened non-modal chooser be changed?
  bool is_force_default() const { return (flags & CH_FORCE_DEFAULT) != 0; }
  /// get number of the built-in chooser
  uint get_builtin_number() const
  {
    return ((flags & CH_BUILTIN_MASK) >> CH_BUILTIN_SHIFT) - 1;
  }
  /// enable or disable generation of ui_get_chooser_item_attrs events
  void set_ask_item_attrs(bool enable)
  {
    if ( enable )
      flags |= CH_ATTRS;
    else
      flags &= ~CH_ATTRS;
  }
  // check chooser version
  void check_version(uint32 ver) const { QASSERT(40217, version >= ver); }
  // should the quick filter be visible at startup?
  bool is_quick_filter_visible_initially() const { return (flags & CH_QFLT) != 0; }
  // what mode should the quick filter initially be put in?
  int get_quick_filter_initial_mode() const { return flags & CH_QFTYP_MASK; }
  // does the chooser have the ability to show a tree view?
  bool has_dirtree() const { return (flags & CH_HAS_DIRTREE) != 0; }
  // does the chooser have the ability to participate in a diff/merge workflow?
  bool has_diff_capability() const { return (flags & CH_HAS_DIFF) != 0; }
  // does chooser have sorting abilities?
  bool can_sort() const { return (flags & CH_NO_SORT) == 0; }
  // does chooser have filtering abilities?
  bool can_filter() const { return (flags & CH_NO_FILTER) == 0; }
  // should renaming trigger the 'edit' callback?
  bool should_rename_trigger_edit() const { return (flags & CH_RENAME_IS_EDIT) != 0; }
  // is the chooser dirtree persisted?
  bool is_dirtree_persisted() const { return (flags & CH_NON_PERSISTED_TREE) == 0; }
  // is the chooser lazy-loaded?
  bool is_lazy_loaded() const { return version >= 3 && (flags2 & CH2_LAZY_LOADED) != 0; }

  /// initialize the chooser and populate it.
  /// \retval false  the chooser is empty, do not display it
  virtual bool idaapi init() { return true; }

  /// get the number of elements in the chooser
  virtual size_t idaapi get_count() const = 0;

  /// get a description of an element.
  /// \param[out] out        vector of strings. \n
  ///                        will receive the contents of each column
  /// \param[out] out_icon   element's icon id, -1 - no icon
  /// \param[out] out_attrs  element attributes
  /// \param n               element number (0..get_count()-1)
  virtual void idaapi get_row(
        qstrvec_t *out,
        int *out_icon,
        chooser_item_attrs_t *out_attrs,
        size_t n) const = 0;


  /// get the address of an element.
  /// When this function returns valid addresses:
  ///  * If any column has the `CHCOL_FNAME` flag, rows will
  ///    be colored according to the attributes of the functions
  ///    who own those addresses (extern, library function,
  ///    Lumina, ... - similar to what the "Functions" widget does)
  ///  * When a selection is present and the user presses `<Enter>`
  ///    (`<Shift+Enter>` if the chooser is modal), IDA will jump
  ///    to that address (through jumpto())
  /// \param n  element number (0-based)
  /// \return  the effective address, BADADDR if the element has no address
  virtual ea_t idaapi get_ea(size_t /*n*/) const { return BADADDR; }

  /// return value of ins(), del(), edit(), enter(), refresh() callbacks
  ///
  /// If the chooser implements get_dirtree(), and has ins() and/or del()
  /// capabilities, the meaning of the returned index(es) combined with
  /// ALL_CHANGED and SELECTION_CHANGED must be as follows:
  ///  - for ins(): the index (in case of a chooser_t, or first index
  ///    in case of a chooser_multi_t), will be the index of the row
  ///    that was inserted.
  ///  - for del(): the index (or indexes in case of a chooser_multi_t),
  ///    will be the index(es) of the row(s) that was(were) deleted.
  enum cbres_t
  {
    NOTHING_CHANGED,
    ALL_CHANGED,
    SELECTION_CHANGED,
  };

  /// The chooser window is closed.
  virtual void idaapi closed() {}

protected:
  // the default labels of the standard actions are different for the qt-
  // and txt-versions of the chooser
  void init_popup_names(const char *const default_popup_names[NSTDPOPUPS])
  {
    for ( int i = 0; i < NSTDPOPUPS; ++i )
      if ( popup_names[i].empty() )
        popup_names[i] = default_popup_names[i];
  }
#ifdef SWIG
  %mutable;
#endif
};

#ifndef SWIG

/// The chooser object without multi-selection.
struct chooser_t : public chooser_base_t
{
  /// Return value of ins(), del(), edit(), enter(), refresh() callbacks
  struct cbret_t
  {
    ssize_t idx;
    cbres_t changed;
    cbret_t() : idx(NO_SELECTION), changed(NOTHING_CHANGED) {}
    cbret_t(ssize_t idx_, cbres_t changed_ = ALL_CHANGED)
      : idx(idx_), changed(changed_) {}
  };

  chooser_t(uint32 flags_ = 0,
            int columns_ = 0,
            const int *widths_ = nullptr,
            const char *const *header_ = nullptr,
            const char *title_ = nullptr,
            uint16 flags2_ = 0)
    : chooser_base_t(
              (flags_ & ~CH_MULTI),
              columns_, widths_, header_,
              title_,
              flags2_) {}

  /// Display a generic list chooser and allow the user to select an item.
  /// May be overridden in derived choosers.
  /// \param deflt  default selection or NO_SELECTION
  /// see the choose() function below
  //lint -sem(chooser_t::choose,custodial(t))
  inline ssize_t choose(ssize_t deflt = 0);

  /// Get the position (index) of the item.
  /// A simple chooser considers `item_data` as an index.
  /// \param  item_data  pointer to some data that identifies the item
  /// \return idx        item index,
  ///                    NO_SELECTION - there is no item with such data
  virtual ssize_t idaapi get_item_index(const void *item_data) const newapi
  {
    // no calculation when `item_data` already is an index
    return *(const ssize_t *)item_data;
  }

  /// Type of ins(), del(), edit(), enter(), refresh() callbacks
  typedef cbret_t (idaapi chooser_t::*cb_t)(size_t n);

  /// User asked to insert an element.
  virtual cbret_t idaapi ins(ssize_t /*n*/) newapi { return cbret_t(); }

  /// User deleted an element.
  /// \param  n        index of the element to delete
  /// \return idx      index of the selected item (cursor)
  ///         changed  what is changed
  virtual cbret_t idaapi del(size_t /*n*/) newapi { return cbret_t(); }

  /// User asked to edit an element.
  /// \param  n        index of the element to edit
  /// \return idx      index of the selected item (cursor)
  ///         changed  what is changed
  virtual cbret_t idaapi edit(size_t /*n*/) newapi { return cbret_t(); } //-V524 body is equal to del()

  /// User pressed the enter key.
  /// \param  n        index of the element where <Enter> was pressed
  /// \retval false    nothing changed
  /// \return idx      index of the selected item (cursor)
  ///         changed  what is changed
  virtual cbret_t idaapi enter(size_t n) newapi
  {
    cbres_t changed = cbres_t(callui(ui_chooser_default_enter, this, &n).i);
    return cbret_t(n, changed);
  }

  /// The chooser needs to be refreshed.
  /// \param  n        index of the selected (current) item
  /// \return idx      new index of the current item
  ///                  (as it may change during refresh)
  ///         changed  what is changed
  virtual cbret_t idaapi refresh(ssize_t n) newapi
  {
    return cbret_t(n, ALL_CHANGED);
  }

  /// Selection changed (cursor moved).
  /// \note This callback is not supported in the txt-version.
  /// \param n  index of the new selected item
  virtual void idaapi select(ssize_t /*n*/) const newapi {}

  /// get the dirtree_t that will be used to present a tree-like
  /// structure to the user (see CH_HAS_DIRTREE)
  /// \return the dirtree_t, or nullptr
  virtual dirtree_t *idaapi get_dirtree() newapi { return nullptr; }

  /// Map an item index to a dirtree_t inode
  /// This is necessary only if CH_HAS_DIRTREE is specified
  /// \param n index of the item
  /// \return the inode number
  virtual inode_t idaapi index_to_inode(size_t /*n*/) const newapi { return inode_t(BADADDR); }

  /// Map an item index to a diffpos_t
  /// This is necessary only if CH_HAS_DIFF is specified
  /// \param n index of the item
  /// \return the diffpos
  virtual diffpos_t idaapi index_to_diffpos(size_t /*n*/) const newapi { return diffpos_t(-1); }

  /// Get the description of the standard chooser actions.
  /// This method is called when creating the chooser widget.
  /// It should fill the array of pointers to the action description.
  /// 'nullptr' means that the default action attributes will be used.
  /// \note Availability of the standard actions is determined by the
  /// CH_CAN_... flags.
  /// \param[out] ucbs  the array of pointers to the description structure
  /// \retval true      UCBS is filled
  /// \retval false     no custom standard actions
  virtual bool idaapi get_stdact_descs(
        chooser_stdact_desc_t * /*descs*/[NSTDPOPUPS]) newapi
  {
    return false;
  }

  /// Callback for lazy-loaded, dirtree-based choosers;
  /// the function will be called when a folder is expanded and it has
  /// not been loaded before. The implementation should use the
  /// given dirtree's link() or mkdir() methods to add the folder contents.
  /// \note The dirtree is chdir()-positioned to the directory being loaded,
  /// so relative paths (like simple filenames) may be useful.
  /// \param dt         dirtree used to fill the directory in
  /// \param dir_path   an absolute dirtree path to this directory
  /// \return success
  virtual bool idaapi do_lazy_load_dir(
        dirtree_t * /*dt*/,
        const qstring & /*dir_path*/) newapi
  {
    return false;
  }

protected:
  ssize_t new_sel_after_del(size_t n) const
  {
    size_t cnt = get_count();
    // assert: n < cnt
    return n + 1 < cnt
         ? n + 1
         : n - 1; // the last item deleted => no selection
  }
  ssize_t adjust_last_item(size_t n) const
  {
    size_t cnt = get_count();
    if ( cnt == 0 )
      return NO_SELECTION;
    // take in account deleting of the last item(s)
    return n < cnt ? n : cnt - 1;
  }
};

/// The chooser object with multi-selection.
struct chooser_multi_t : public chooser_base_t
{
  chooser_multi_t(
          uint32 flags_ = 0,
          int columns_ = 0,
          const int *widths_ = nullptr,
          const char *const *header_ = nullptr,
          const char *title_ = nullptr,
          uint16 flags2_ = 0)
    : chooser_base_t(
              flags_ | CH_MULTI,
              columns_, widths_, header_,
              title_,
              flags2_) {}

  /// Display a generic list chooser and allow the user to select an item.
  /// May be overridden in derived choosers.
  /// \param deflt  default selection (may be empty)
  /// see the choose() function below
  //lint -sem(chooser_multi_t::choose,custodial(t))
  inline ssize_t choose(const sizevec_t &deflt = sizevec_t());

  /// Get the positions of the items.
  /// A simple chooser considers `item_data` as a list of indexes.
  /// \param[in,out] sel  items indexes
  /// \param item_data    pointer to some data that identifies the items
  virtual void idaapi get_item_index(
        sizevec_t *sel,
        const void *item_data) const newapi
  {
    // no calculation when `item_data` already is a vector
    *sel = *(const sizevec_t *)item_data;
  }

  /// Type of ins(), del(), edit(), enter(), refresh() callbacks
  typedef cbres_t (idaapi chooser_multi_t::*cb_t)(sizevec_t *sel);

  /// User asked to insert an element.
  virtual cbres_t idaapi ins(sizevec_t * /*sel*/) newapi
  {
    return NOTHING_CHANGED;
  }

  /// User deleted elements.
  /// \param[in,out] sel  selected items
  /// \return             what is changed
  virtual cbres_t idaapi del(sizevec_t * /*sel*/) newapi
  {
    return NOTHING_CHANGED;
  }

  /// User asked to edit an element.
  /// \param[in,out] sel  selected items
  /// \return             what is changed
  virtual cbres_t idaapi edit(sizevec_t * /*sel*/) newapi
  {
    return NOTHING_CHANGED;
  }

  /// User pressed the enter key.
  /// \param[in,out] sel  selected items
  /// \return             what is changed
  virtual cbres_t idaapi enter(sizevec_t *sel) newapi
  {
    return cbres_t(callui(ui_chooser_default_enter, this, sel).i);
  }

  /// The chooser needs to be refreshed.
  /// It returns the new positions of the selected items.
  /// \param[in,out] sel  selected items
  /// \return             what is changed
  virtual cbres_t idaapi refresh(sizevec_t * /*sel*/) newapi
  {
    return ALL_CHANGED;
  }

  /// Selection changed
  /// \note This callback is not supported in the txt-version.
  /// \param sel  new selected items
  virtual void idaapi select(const sizevec_t &/*sel*/) const newapi {}

  /// get the dirtree_t that will be used to present a tree-like
  /// structure to the user (see CH_HAS_DIRTREE)
  /// \return the dirtree_t, or nullptr
  virtual dirtree_t *idaapi get_dirtree() newapi { return nullptr; }

  /// Map an item index to a dirtree_t inode
  /// This is necessary only if CH_HAS_DIRTREE is specified
  /// \param n index of the item
  /// \return the inode number
  virtual inode_t idaapi index_to_inode(size_t /*n*/) const newapi { return inode_t(BADADDR); }

  /// Map an item index to a diffpos_t
  /// This is necessary only if CH_HAS_DIFF is specified
  /// \param n index of the item
  /// \return the diffpos
  virtual diffpos_t idaapi index_to_diffpos(size_t /*n*/) const newapi { return diffpos_t(-1); }

  /// Get the description of the standard chooser actions.
  /// This method is called when creating the chooser widget.
  /// It should fill the array of pointers to the action description.
  /// 'nullptr' means that the default action attributes will be used.
  /// \note Availability of the standard actions is determined by the
  /// CH_CAN_... flags.
  /// \param[out] ucbs  the array of pointers to the description structure
  /// \retval true      UCBS is filled
  /// \retval false     no custom standard actions
  virtual bool idaapi get_stdact_descs(
        chooser_stdact_desc_t * /*descs*/[NSTDPOPUPS]) newapi
  {
    return false;
  }

  /// Callback for lazy-loaded, dirtree-based choosers;
  /// the function will be called when a folder is expanded and it has
  /// not been loaded before. The implementation should use the
  /// given dirtree's link() or mkdir() methods to add the folder contents.
  /// \note The dirtree is chdir()-positioned to the directory being loaded,
  /// so relative paths (like simple filenames) may be useful.
  /// \param dt         dirtree used to fill the directory in
  /// \param dir_path   an absolute dirtree path to this directory
  /// \return success
  virtual bool idaapi do_lazy_load_dir(
        dirtree_t * /*dt*/,
        const qstring & /*dir_path*/) newapi
  {
    return false;
  }

protected:
  // used in the del() callback to iterate
  static bool next_item_to_del(sizevec_t *sel);
  ssize_t new_sel_after_del(const sizevec_t &sel) const;
  void adjust_last_item(sizevec_t *sel, size_t n) const;
};


/// Multi line text control, used to embed a text control in a form
struct textctrl_info_t
{
  size_t  cb;                 ///< size of this structure
  qstring text;               ///< in, out: text control value
  uint16  flags;              ///< \ref TXTF_
/// \defgroup TXTF_ Text control property bits
/// used by textctrl_info_t::flags
//@{
#define TXTF_AUTOINDENT  0x0001 ///< auto-indent on new line
#define TXTF_ACCEPTTABS  0x0002 ///< Tab key inserts 'tabsize' spaces
#define TXTF_READONLY    0x0004 ///< text cannot be edited (but can be selected and copied)
#define TXTF_SELECTED    0x0008 ///< shows the field with its text selected
#define TXTF_MODIFIED    0x0010 ///< gets/sets the modified status
#define TXTF_FIXEDFONT   0x0020 ///< the control uses IDA's fixed font
#define TXTF_LINENUMBERS 0x0040 ///< the text editor widget should display line numbers
#define TXTF_HTML        0x0080 ///< Text will be rendered as html
                                ///< (only enabled if TXTF_READONLY, gui-only)
//@}
  uint16  tabsize;            ///< how many spaces a single tab will indent
  textctrl_info_t(): cb(sizeof(textctrl_info_t)), flags(0), tabsize(0) {} ///< Constructor
};

/// \defgroup choosers Functions: generic list choosers
/// These functions display a window that allows the user to select items
//@{


/// Display a generic list chooser (n-column) and allow the user to select
/// an item.
/// The closed() callback will be called when the window is closed.
/// In addition, after the window is closed, the chooser instance
/// will be delete()d unless CH_KEEP is specified (useful for global, or
/// stack-allocated chooser instances, that must not be deleted.)
/// \param ch        pointer to the chooser object
/// \param def_item  pointer to some data that identifies the default item
/// For modal choosers:
/// \return   the index of the selected item (0-based)
/// \retval chooser_base_t::NO_SELECTION    the user refused to choose
///           anything (pressed Esc).
/// \retval chooser_base_t::EMPTY_CHOOSER   the chooser was not created
///           because the init() callback returned 'false'
/// For non-modal choosers:
/// \retval 0                               the chooser was created
///                                         successfully
/// \retval chooser_base_t::ALREADY_EXISTS  did not open a new chooser
///           because a chooser with the same object is already open. If
///           CH_FORCE_DEFAULT was set, the cursor of the chooser will be
///           positioned to the new item.
/// \retval chooser_base_t::EMPTY_CHOOSER   the chooser was not created
///           because CH_FORCE_DEFAULT was set and the init() callback
///           returned 'false'

//lint -sem(choose,custodial(1))
ssize_t choose(chooser_base_t *ch, const void *def_item);

inline ssize_t chooser_t::choose(ssize_t deflt)
{
  // chooser uses the default implementation of the get_item_index()
  // callback
  return ::choose(this, &deflt);
}

inline ssize_t chooser_multi_t::choose(const sizevec_t &deflt)
{
  // chooser uses the default implementation of the get_item_index()
  // callback
  return ::choose(this, &deflt);
}

//@}

#endif // SWIG

//-------------------------------------------------------------------------
enum navaddr_type_t
{
  nat_lib = 0,
  nat_fun,
  nat_cod,
  nat_dat,
  nat_und,
  nat_ext,
  nat_err,
  nat_gap,
  nat_cur,
  nat_auto, // auto-analysis cursor color
  nat_lum,  // related to lumina
  nat_hlo,  // highlight outline
  nat_last
};

/// Navigation band colorizer function.
///
/// If ea==BADADDR, then 'nbytes' is a navaddr_type_t, and the colorizer
/// is in charge of returning the color associated to that type of address.
/// This is used for maintaining the legend in-sync with the colors used to
/// display the addresses in the navigation bar.
///
/// \param ea      address to calculate the color of, or BADADDR (see above)
/// \param nbytes  number of bytes, this can be ignored for quick&dirty approach
/// \param ud      user data
/// \return color of the specified address in RGB

typedef uint32 idaapi nav_colorizer_t(ea_t ea, asize_t nbytes, void *ud);


/// Install new navigation band colorizer (::ui_set_nav_colorizer).

inline void set_nav_colorizer(
        nav_colorizer_t **out_was_func,
        void **out_was_ud,
        nav_colorizer_t *func,
        void *ud)
{
  callui(ui_set_nav_colorizer, out_was_func, out_was_ud, func, ud);
}

/// Custom viewer & code viewer handler types
enum custom_viewer_handler_id_t
{
  CVH_USERDATA,
  CVH_KEYDOWN,               ///< see ::custom_viewer_keydown_t
  CVH_POPUP,                 ///< see ::custom_viewer_popup_t
  CVH_DBLCLICK,              ///< see ::custom_viewer_dblclick_t
  CVH_CURPOS,                ///< see ::custom_viewer_curpos_t
  CVH_CLOSE,                 ///< see ::custom_viewer_close_t
  CVH_CLICK,                 ///< see ::custom_viewer_click_t
  CVH_QT_AWARE,              ///< see set_custom_viewer_qt_aware()
  CVH_HELP,                  ///< see ::custom_viewer_help_t
  CVH_MOUSEMOVE,             ///< see ::custom_viewer_mouse_moved_t

  CDVH_USERDATA = 1000,      ///< see set_code_viewer_user_data()
  CDVH_SRCVIEW,              ///< see set_code_viewer_is_source()
  CDVH_LINES_CLICK,          ///< see ::code_viewer_lines_click_t
  CDVH_LINES_DBLCLICK,       ///< see ::code_viewer_lines_click_t
  CDVH_LINES_POPUP,          ///< see ::code_viewer_lines_click_t
  CDVH_LINES_DRAWICON,       ///< see ::code_viewer_lines_icon_t
  CDVH_LINES_LINENUM,        ///< see ::code_viewer_lines_linenum_t
  CDVH_LINES_ICONMARGIN,     ///< see set_code_viewer_lines_icon_margin()
  CDVH_LINES_RADIX,          ///< see set_code_viewer_lines_radix()
  CDVH_LINES_ALIGNMENT       ///< see set_code_viewer_lines_alignment()
};

//-------------------------------------------------------------------------
/// state & 1 => Shift is pressed                 \n
/// state & 2 => Alt is pressed                   \n
/// state & 4 => Ctrl is pressed                  \n
/// state & 8 => Mouse left button is pressed     \n
/// state & 16 => Mouse right button is pressed   \n
/// state & 32 => Mouse middle button is pressed  \n
/// state & 128 => Meta is pressed (OSX only)
#define VES_SHIFT        (1 << 0)
#define VES_ALT          (1 << 1)
#define VES_CTRL         (1 << 2)
#define VES_MOUSE_LEFT   (1 << 3)
#define VES_MOUSE_RIGHT  (1 << 4)
#define VES_MOUSE_MIDDLE (1 << 5)
#define VES_META         (1 << 7)
typedef int input_event_modifiers_t;
typedef input_event_modifiers_t view_event_state_t;

//-------------------------------------------------------------------------
/// Notification codes for events in the message window
enum msg_notification_t
{
  msg_activated,    ///< The message window is activated.
                    ///< \param none
                    ///< \return void

  msg_deactivated,  ///< The message window is deactivated.
                    ///< \param none
                    ///< \return void

  msg_click,        ///< Click event.
                    ///< \param x      (int) x-coordinate
                    ///< \param y      (int) y-coordinate
                    ///< \param state  (::view_event_state_t)
                    ///< \retval 1 handled
                    ///< \retval 0 not handled (invoke default handler)

  msg_dblclick,     ///< Double click event.
                    ///< \param x      (int) x-coordinate
                    ///< \param y      (int) y-coordinate
                    ///< \param state  (::view_event_state_t)
                    ///< \retval 1 handled
                    ///< \retval 0 not handled (invoke default handler)

  msg_closed,       ///< View closed.
                    ///< \param none
                    ///< \return void

  msg_keydown,      ///< Key down event.
                    ///< \param key    (int)
                    ///< \param state  (::view_event_state_t)
                    ///< \retval 1 handled
                    ///< \retval 0 not handled (invoke default handler)
};

//-------------------------------------------------------------------------
/// Information about a position relative to the renderer
struct renderer_pos_info_t
{
  /// Constructor
  renderer_pos_info_t() : node(-1), cx(-1), cy(-1), sx(-1) {}

  int node; ///< the node, or -1 if the current renderer
            ///< is not a graph renderer.

  short cx; ///< the X coords of the character in the current line.
            ///< When in graph mode: X coords of the character in 'node'.       \n
            ///< When in flat mode: X coords of the character in the line, w/o  \n
            ///< taking scrolling into consideration.

  short cy; ///< the Y coords of the character.
            ///< When in graph mode: Y coords of the character in 'node'.       \n
            ///< When in flat mode: Line number, starting from the top.

  short sx; ///< the number of chars that are scrolled (flat mode only)

  bool operator == (const renderer_pos_info_t &r) const
    { return node == r.node && cx == r.cx && cy == r.cy && sx == r.sx; }
  bool operator != (const renderer_pos_info_t &r) const
    { return !(*this == r); }
};

//-------------------------------------------------------------------------
struct selection_item_t;

//-------------------------------------------------------------------------
/// Abstraction of location in flat view/graph views
/// (out of 'view_mouse_event_t' to make it easy for SWiG to wrap)
union view_mouse_event_location_t
{
  ea_t ea;                        ///< flat view (rtype == ::TCCRT_FLAT)
  const selection_item_t *item;   ///< graph views (rtype != ::TCCRT_FLAT).
                                  ///< nullptr if mouse is not currently over an item.
};


/// Information about a mouse action within a view
struct view_mouse_event_t
{
  tcc_renderer_type_t rtype;        ///< type of renderer that received the event

  uint32 x;                         ///< screen x coordinate
  uint32 y;                         ///< screen y coordinate

  typedef view_mouse_event_location_t location_t;
  location_t location;              ///< location where event was generated

  view_event_state_t state;         ///< contains information about what buttons are CURRENTLY pressed
                                    ///< on the keyboard and mouse. view_mouse_event_t instances created
                                    ///< in functions like mouseReleaseEvent() won't contain any information
                                    ///< about the mouse, because it has been released.

  vme_button_t button;              ///< represents which mouse button was responsible for generating the event.
                                    ///< This field does not care about the current state of the mouse.

  renderer_pos_info_t renderer_pos; ///< position where event was generated, relative to the renderer
};

//-------------------------------------------------------------------------
/// Notification codes sent by the UI for IDAView or custom viewer events.
/// These notification codes should be used together with ::HT_VIEW hook type.
enum view_notification_t
{
  view_activated,    ///< A view is activated
                     ///< \param view  (TWidget *)

  view_deactivated,  ///< A view is deactivated
                     ///< \param view  (TWidget *)

  view_keydown,      ///< Key down event
                     ///< \param view   (TWidget *)
                     ///< \param key    (int)
                     ///< \param state  (::view_event_state_t)

  view_click,        ///< Click event
                     ///< \param view   (TWidget *)
                     ///< \param event  (const ::view_mouse_event_t *)

  view_dblclick,     ///< Double click event
                     ///< \param view   (TWidget *)
                     ///< \param event  (const ::view_mouse_event_t *)

  view_curpos,       ///< Cursor position changed
                     ///< \param view  (TWidget *)

  view_created,      ///< A view is being created.
                     ///< \param view  (TWidget *)

  view_close,        ///< View closed
                     ///< \param view  (TWidget *)

  view_switched,     ///< A view's renderer has changed.
                     ///< \param view  (TWidget *)
                     ///< \param rt    (::tcc_renderer_type_t)

  view_mouse_over,   ///< The user moved the mouse over (or out of) a node or an edge.
                     ///< This is only relevant in a graph view.
                     ///< \param view   (TWidget *)
                     ///< \param event  (const ::view_mouse_event_t *)

  view_loc_changed,  ///< The location for the view has changed (can be either
                     ///< the place_t, the renderer_info_t, or both.)
                     ///< \param view  (TWidget *)
                     ///< \param now   (const lochist_entry_t *)
                     ///< \param was   (const lochist_entry_t *)

  view_mouse_moved,  ///< The mouse moved on the view
                     ///< \param view  (TWidget *)
                     ///< \param event (const ::view_mouse_event_t *)
};

#ifndef SWIG

/// The user has pressed a key

typedef bool idaapi custom_viewer_keydown_t(TWidget *cv, int vk_key, int shift, void *ud);


/// The user right clicked. See ::ui_populating_widget_popup, too.

typedef void idaapi custom_viewer_popup_t(TWidget *cv, void *ud);


/// The user moved the mouse.

typedef void idaapi custom_viewer_mouse_moved_t(TWidget *cv, int shift, view_mouse_event_t *e, void *ud);


/// The user clicked

typedef bool idaapi custom_viewer_click_t(TWidget *cv, int shift, void *ud);


/// The user double clicked

typedef bool idaapi custom_viewer_dblclick_t(TWidget *cv, int shift, void *ud);


/// Deprecated.
///
/// See custom_viewer_location_changed_t for a more
/// competent, and general solution.

typedef void idaapi custom_viewer_curpos_t(TWidget *cv, void *ud);


/// Custom viewer is being destroyed

typedef void idaapi custom_viewer_close_t(TWidget *cv, void *ud);


/// Custom viewer: the user pressed F1
/// If the return value != -1, it is treated as a help context to display (from ida.hlp)

typedef int idaapi custom_viewer_help_t(TWidget *cv, void *ud);


/// Fine-tune 'loc->place()' according to the X position (i.e., 'loc->renderer_info().pos.cx')
///
/// You can consider that the place_t object is a 'row cursor' in the
/// list of lines that fill the screen. But, it is only a 'vertical'
/// cursor: e.g., the simpleline_place_t has the 'n' mumber, which
/// specifies what line the place_t corresponds to, in the backing
/// strvec_t instance.
////
/// However, some views have a place that can be sensitive to the X
/// coordinates of the view's cursor. Think of the "Hex View-1", or
/// the "Pseudocode-A" views: when moving the cursor on the X axis,
/// the 'row cursor' will not change (since we are moving on the same
/// line), but the corresponding 'ea_t' might.
///
/// For such tricky situations, we provide the following callback, that
/// will provide the ability to update the 'loc->place()'s internal state
/// according to 'loc->renderer_info().pos.cx' so
/// that it really reflects the current cursor position.
/// Most custom viewers will not need to implement this, but if some data
/// in your place_t instances is dependent upon the X coordinate of the
/// cursor, you'll probably want to.
///
/// Called whenever the user moves the cursor around (mouse, keyboard)
///
/// Note: this callback should only ever read 'loc->renderer_info()',
/// not modify it. Doing so will result in undefined behavior.

typedef void idaapi custom_viewer_adjust_place_t(TWidget *v, lochist_entry_t *loc, void *ud);


/// Does the line pointed to by pline include pitem, and if so at what X coordinate?
///
/// place_t instances can be considered as a 'cursor' in a set of lines (see
/// custom_viewer_adjust_place_t), but they can be 'tuned' to
/// correctly represent the current position (e.g., hexrays decompiler plugins
/// tune its place_t instances so they contain the real, current 'ea_t', that
/// corresponds to the C-like expression that's shown at the X coordinate
/// within that line.)
///
/// But then, when the viewer has to determine whether a certain twinline_t
/// in fact displays the current place, the sublcass's implementation of
/// place_t::compare() might lead it to think that the current twinline_t's
/// place_t is not correct (e.g., because the 'ea_t' has been fine-tuned
/// according to the caret's X coordinates.)
///
/// Thus, if your plugin implements custom_viewer_adjust_place_t,
/// you probably want to implement this as well, or refreshes might be
/// unnecessarily frequent, leading to a worse user experience.
///
/// This is typically called when the user moves the cursor around.
/// return
///    -1 if pitem is not included in pline
///    -2 pitem points to the entire line
///    >= 0 for the X coordinate within the pline, where pitem points

typedef int idaapi custom_viewer_get_place_xcoord_t(TWidget *v, const place_t *pline, const place_t *pitem, void *ud);


enum locchange_reason_t
{
  lcr_unknown,
  lcr_goto,
  lcr_user_switch, // user pressed <Space>
  lcr_auto_switch, // automatic switch
  lcr_jump,
  lcr_navigate,    // navigate back & forward
  lcr_scroll,      // user used scrollbars
  lcr_internal,    // misc. other reasons
};

#define LCMD_SYNC (1 << 0)
class locchange_md_t // location change metadata
{
protected:
  uchar cb;
  uchar r;
  uchar f;
  uchar reserved;

public:
  locchange_md_t(locchange_reason_t _reason, bool _sync)
    : cb(sizeof(*this)), r(uchar(_reason)), f(_sync ? LCMD_SYNC : 0), reserved(0) {}
  locchange_reason_t reason() const { return locchange_reason_t(r); }
  bool is_sync() const { return (f & LCMD_SYNC) != 0; }
};
CASSERT(sizeof(locchange_md_t) == sizeof(uint32));
DECLARE_TYPE_AS_MOVABLE(locchange_md_t);

/// The user asked to navigate to the given location.
///
/// This gives the view the possibility of declining the move.
/// Reasons for this can be:
///  - the location cannot be displayed,
///  - going there requires a long-running operation, that can be
///    canceled by the user (e.g., in case of the hexrays plugins:
///    during decompilation of the target function.)
///  - ...
///
/// This is called before the new location is committed to the view's history.
///
/// return
///    0 if the move is accepted
///    != 0 otherwise

typedef int idaapi custom_viewer_can_navigate_t(
        TWidget *v,
        const lochist_entry_t *now,
        const locchange_md_t &md,
        void *ud);


/// The viewer's location (i.e., place, or cursor) changed.

typedef void idaapi custom_viewer_location_changed_t(
        TWidget *v,
        const lochist_entry_t *was,
        const lochist_entry_t *now,
        const locchange_md_t &md,
        void *ud);


// Code viewer handlers for the lineinfo widget located to the left of the text.

/// The user clicked, right clicked or double clicked.
/// pos: the clicked icon number. -1 means the click occurred on space not reserved to icons.

typedef void idaapi code_viewer_lines_click_t(TWidget *c, const place_t *p, int pos, int shift, void *ud);


/// Retrieve an icon for a code viewer line.
/// Icons are drawn on the gutter to the left of the code viewer text.
/// Multiple icons can be drawn for a line. Each icon has its position (the leftmost
/// icon has the position 0, the next one has the position 1, etc).
/// \param cv   pointer to the code viewer
/// \param p    the line position in the code viewer for which retrieve the icon
/// \param pos  the icon number, will be 0,1,2,3... \n
///             can be modified to skip positions and draw at the specified one
/// \param ud   user data of the code viewer
/// \return the id of the icon to draw. If bitwise or'ed with 0x80000000,
///         IDA calls this function once more with pos+1 to retrieve one more icon.

typedef int idaapi code_viewer_lines_icon_t(TWidget *cv, const place_t *p, int *pos, void *ud);


/// Calculate the line number. Return false to not print any number.

typedef bool idaapi code_viewer_lines_linenum_t(TWidget *cv, const place_t *p, uval_t *num, void *ud);

#endif // SWIG

//-------------------------------------------------------------------------
enum input_event_kind_t
{
  iek_unknown = 0,
  iek_shortcut,
  iek_key_press,
  iek_key_release,
  iek_mouse_button_press,
  iek_mouse_button_release,
  iek_mouse_wheel,
};

//-------------------------------------------------------------------------

/// A representation of a user input

struct input_event_t
{
  int cb;                            ///< size marker
  input_event_kind_t kind;           ///< the kind of event
  input_event_modifiers_t modifiers; ///< current keyboard (and mouse) modifiers
  TWidget *target;                   ///< the target widget
  void *source;                      ///< the source event, should it be required for detailed inform (e.g., a QEvent in the GUI version of IDA)

  struct input_event_shortcut_data_t
  {
    const char *action_name;         ///< the action that will be triggered
  };
  struct input_event_keyboard_data_t
  {
    int key;                         ///< the key that was pressed to generate the event
    char text[8];                    ///< textual representation of the key
  };
  struct input_event_mouse_data_t
  {
    int x;                           ///< the X position on the widget
    int y;                           ///< the Y position on the widget
    vme_button_t button;             ///< the button that was pressed to generate the event
  };

  union
  {
    input_event_shortcut_data_t shortcut;
    input_event_keyboard_data_t keyboard;
    input_event_mouse_data_t mouse;
  };

  input_event_t()
  {
    memset(this, 0, sizeof(*this));
    cb = sizeof(*this);
  }
};

//------------------------------------------------------------------------

/// Command line interpreter.
/// Provides functionality for the command line (located at the bottom of the main window).
/// Only GUI version of IDA supports CLIs.
struct cli_t
{
  size_t size;                  ///< size of this structure
  int32 flags;                  ///< \ref CLIF_
/// \defgroup CLIF_ CLI attributes
/// used by cli_t::flags
//@{
#define CLIF_QT_AWARE    1      ///< keydown event will use Qt key codes
//@}
  const char *sname;            ///< short name (displayed on the button)
  const char *lname;            ///< long name (displayed in the menu)
  const char *hint;             ///< hint for the input line

  /// Callback: the user pressed Enter.
  /// CLI is free to execute the line immediately or ask for more lines.
  /// \param  line   command to execute (utf-8-encoded)
  /// \retval true   executed line
  /// \retval false  ask for more lines
  bool (idaapi *execute_line)(const char *line);

  void *unused;

  /// Callback: a keyboard key has been pressed.
  /// This callback is optional.
  /// It is a generic callback and the CLI is free to do whatever it wants.
  /// \param line      current input line (in/out argument)
  /// \param p_x       pointer to current x coordinate of the cursor (in/out)
  /// \param p_sellen  pointer to current selection length (usually 0)
  /// \param p_vk_key  pointer to virtual key code (in/out).
  ///                   if the key has been handled, it should be reset to 0 by CLI
  /// \param shift     shift state
  /// \retval true modified input line or x coordinate or selection length
  /// \retval false otherwise
  bool (idaapi *keydown)(
        qstring *line,
        int *p_x,
        int *p_sellen,
        int *p_vk_key,
        int shift);

  /// Callback: the user pressed Tab/Shift+Tab.
  /// This callback is optional.
  /// \param[out] out_completions results of completion
  /// \param[out] out_match_start the codepoint index in the line, where match starts
  /// \param[out] out_match_end   the codepoint index in the line, where ends ends
  /// \param line                 command line
  /// \param x                    codepoint index of the cursor in line
  /// \retval true                got results
  /// \retval false               otherwise
  bool (idaapi *find_completions)(
          qstrvec_t *out_completions,
          int *out_match_start,
          int *out_match_end,
          const char *line,
          int x);
};

//---------------------------------------------------------------------------
/// \defgroup MFF_ Exec request flags
/// passed as 'reqf' parameter to execute_sync()
//@{
#define MFF_FAST   0x0000       ///< Execute code as soon as possible.
                                ///< this mode is ok for calling ui related functions
                                ///< that do not query the database.

#define MFF_READ   0x0001       ///< Execute code only when ida is idle and it is safe
                                ///< to query the database.
                                ///< This mode is recommended only
                                ///< for code that does not modify the database.
                                ///< (nb: ida may be in the middle of executing
                                ///< another user request, for example it may be waiting
                                ///< for him to enter values into a modal dialog box)

#define MFF_WRITE  0x0002       ///< Execute code only when ida is idle and it is safe
                                ///< to modify the database. in particular,
                                ///< this flag will suspend execution if there is
                                ///< a modal dialog box on the screen.
                                ///< this mode can be used to call any ida api function.
                                ///< #MFF_WRITE implies #MFF_READ

#define MFF_NOWAIT 0x0004       ///< Do not wait for the request to be executed.
                                ///< the caller should ensure that the request is not
                                ///< destroyed until the execution completes.
                                ///< if not, the request will be ignored.
                                ///< the request must be created using the 'new' operator
                                ///< to use it with this flag.
                                ///< it can be used in cancel_exec_request().
                                ///< This flag can be used to delay the code execution
                                ///< until the next UI loop run even from the main thread.
//@}


/// Execute code in the main thread - to be used with execute_sync().
struct exec_request_t
{
  /// Internal magic
  enum { MFF_MAGIC = 0x12345678 };

  /// Can this request be executed?
  bool valid(void) const
  {
    return (code & ~7) == MFF_MAGIC && (sem != nullptr || (code & MFF_NOWAIT) != 0);
  }

  int code;           ///< temporary location, used internally

  qsemaphore_t sem;   ///< semaphore to communicate with the main thread.
                      ///< If nullptr, will be initialized by execute_sync().

  /// Callback to be executed.
  /// If this function raises an exception, execute_sync() never returns.
  virtual int idaapi execute(void) = 0;

  /// Constructor
  exec_request_t(void) : code(0), sem(nullptr) {}

  /// Destructor
  // FIXME: windows: gcc compiled plugins cannot use exec_request_t because the destructor
  // is generated differently!
  virtual ~exec_request_t(void) { qsem_free(sem); sem = nullptr; code = 0; }
};

//---------------------------------------------------------------------------
/// Base class for defining UI requests.
/// Override the run() method and insert your code.
class ui_request_t
{
public:
  /// Run the UI request
  /// \retval false  remove the request from the queue
  /// \retval true   reschedule the request and run it again
  virtual bool idaapi run() = 0;
  virtual ~ui_request_t() {}
};

/// List of UI requests. The ui_request_t is allocated by the caller
/// but its ownership is transferred to the execute_ui_requests().
/// The ui_request_t instance will be deleted as soon as it is executed and
/// was not rescheduled for another run.
class ui_requests_t : public qlist<ui_request_t *>
{
  DECLARE_UNCOPYABLE(ui_requests_t)
public:
  ui_requests_t() {}  ///< Constructor
  ~ui_requests_t()    ///< Destructor
  {
    for ( iterator p=begin(); p != end(); ++p )
      delete *p;
  }
};

/// Snapshot restoration completion callback. see restore_database_snapshot()
typedef void idaapi ss_restore_cb_t(const char *errmsg, void *ud);

/// \defgroup UIJMP_ Jump flags
/// passed as 'uijmp_flags' parameter to jumpto()
//@{
#define UIJMP_ACTIVATE        0x0001  ///< activate the new window
#define UIJMP_DONTPUSH        0x0002  ///< do not remember the current address
                                      ///< in the navigation history
#define UIJMP_VIEWMASK        0x000C
#define UIJMP_ANYVIEW         0x0000  ///< jump in any ea_t-capable view
#define UIJMP_IDAVIEW         0x0004  ///< jump in idaview
#define UIJMP_IDAVIEW_NEW     0x0008  ///< jump in new idaview
//@}

struct screen_graph_selection_t;
struct dirtree_selection_t;
typedef uval_t const_t;

//-------------------------------------------------------------------------
// Current selection
struct action_ctx_base_cur_sel_t
{
  twinpos_t from;      ///< start of selection
  twinpos_t to;        ///< end of selection

  action_ctx_base_cur_sel_t() { reset(); }
  void reset()
  {
    from.at = nullptr;
    from.x = -1;
    to.at = nullptr;
    to.x = -1;
  }
};

//-------------------------------------------------------------------------
union action_ctx_base_source_t
{
  chooser_base_t *chooser;

  action_ctx_base_source_t() { reset(); }
  void reset()
  {
    chooser = nullptr;
  }
};

//-------------------------------------------------------------------------
/// Maintain information about the current state of the UI.
/// This allows actions to behave appropriately (see ::action_handler_t)
struct action_ctx_base_t
{
  /// Constructor
  action_ctx_base_t()
  {
    reset();
  }

/// \defgroup ACF_ Action context property bits
/// used by action_ctx_base_t::cur_flags
//@{
#define ACF_HAS_SELECTION               (1 << 0) ///< there is currently a valid selection
#define ACF_XTRN_EA                     (1 << 1) ///< cur_ea is in 'externs' segment
#define ACF_HAS_FIELD_DIRTREE_SELECTION (1 << 2) ///< 'cur_enum_member' and 'dirtree_selection' fields are present
#define ACF_HAS_SOURCE                  (1 << 3) ///< 'source' field is present
//@}

  /// Invalidate all context info
  void reset()
  {
    widget = nullptr;
    widget_type = BWN_UNKNOWN;
    widget_title.clear();
    chooser_selection.clear();
    action = nullptr;

    //
    cur_flags = ACF_HAS_FIELD_DIRTREE_SELECTION | ACF_HAS_SOURCE;
    cur_ea = BADADDR;
    cur_value = BADADDR;
    cur_func = cur_fchunk = nullptr;
    cur_struc = nullptr; cur_strmem = nullptr;
    cur_enum = enum_t(-1);
    cur_seg = nullptr;
    cur_sel.reset();
    regname = nullptr;
    focus = nullptr;
    graph_selection = nullptr;
    cur_enum_member = const_t(-1);
    dirtree_selection = nullptr;
    source.reset();
  }
  TWidget *widget;
  twidget_type_t widget_type;     ///< type of current widget
  qstring widget_title;           ///< title of current widget
  sizevec_t chooser_selection;    ///< current chooser selection (0-based)
  const char *action;             ///< action name

  uint32 cur_flags; ///< Current address information. see \ref ACF_

  /// Check if the given flag is set
  bool has_flag(uint32 flag) const { return (cur_flags & flag) == flag; }

  ea_t cur_ea;           ///< the current EA of the position in the view
  uval_t cur_value;      ///< the possible address, or value the cursor is positioned on

  func_t *cur_func;      ///< the current function
  func_t *cur_fchunk;    ///< the current function chunk

  struc_t *cur_struc;    ///< the current structure
  member_t *cur_strmem;  ///< the current structure member

  enum_t cur_enum;       ///< the current enum

  segment_t *cur_seg;    ///< the current segment

  action_ctx_base_cur_sel_t cur_sel; ///< the currently selected range. also see #ACF_HAS_SELECTION

  const char *regname;   ///< register name (if widget_type == BWN_CPUREGS and context menu opened on register)

  TWidget *focus;        ///< The focused widget in case it is not the 'form' itself (e.g., the 'quick filter' input in choosers.)

  screen_graph_selection_t *graph_selection; ///< the current graph selection (if in a graph view)
  const_t cur_enum_member;

  dirtree_selection_t *dirtree_selection; ///< the current dirtree_t selection (if applicable)

  action_ctx_base_source_t source; ///< the underlying chooser_base_t (if 'widget' is a chooser widget)
};

//-------------------------------------------------------------------------
/// Instances of this class will be filled with information that is
/// commonly used by actions when they need to
/// be activated. This is so they don't have to perform (possibly)
/// costly operations more than once.
typedef action_ctx_base_t action_activation_ctx_t;

//-------------------------------------------------------------------------
/// Instances of this class will be filled with information that is
/// commonly used by actions when they need to
/// update. This is so they don't have to perform (possibly)
/// costly operations more than once.
typedef action_ctx_base_t action_update_ctx_t;

#define AHF_VERSION 1          ///< action handler version (used by action_handler_t::flags)
#define AHF_VERSION_MASK 0xFF  ///< mask for action_handler_t::flags

//-------------------------------------------------------------------------
/// Manages the behavior of a registered action
struct action_handler_t
{
  int flags;  ///< internal - for version management

  /// Constructor
  action_handler_t(int _f = 0) : flags(_f) { flags |= AHF_VERSION; }

  /// Activate an action.
  /// This function implements the core behavior of an action.
  /// It is called when the action is triggered, from a menu, from
  /// a popup menu, from the toolbar, or programmatically.
  /// \returns non-zero: all IDA windows will be refreshed
  virtual int idaapi activate(action_activation_ctx_t *ctx) = 0;

  /// Update an action.
  /// This is called when the context of the UI changed, and we need to let the
  /// action update some of its properties if needed (label, icon, ...)
  ///
  /// In addition, this lets IDA know whether the action is enabled,
  /// and when it should be queried for availability again.
  ///
  /// Note: This callback is not meant to change anything in the
  /// application's state, except by calling one (or many) of
  /// the "update_action_*()" functions on this very action.
  virtual action_state_t idaapi update(action_update_ctx_t *ctx) = 0;

  /// Destructor
  virtual ~action_handler_t() {}

  // Action handles may be allocated by a plugin and deleted by the kernel.
  // Therefore it is a good idea to unify the memory allocation methods.
  DEFINE_MEMORY_ALLOCATION_FUNCS();
};

/// Describe an action to be registered (see register_action())
struct action_desc_t
{
  int cb;                    ///< size of this structure
  const char *name;          ///< the internal name of the action; must be unique.
                             ///< a way to reduce possible conflicts is to prefix it
                             ///< with some specific prefix. E.g., "myplugin:doSthg".

  const char *label;         ///< the label of the action, possibly with an accelerator
                             ///< key definition (e.g., "~J~ump to operand")

  action_handler_t *handler; ///< the action handler, for activating/updating.
                             ///< please read the comments at register_action().

  const void *owner;         ///< either the plugin_t, or plugmod_t responsible for
                             ///< registering the action. Can be nullptr
                             ///< Please see \ref ACTION_DESC_LITERAL_PLUGMOD

  const char *shortcut;      ///< an optional shortcut definition. E.g., "Ctrl+Enter"
  const char *tooltip;       ///< an optional tooltip for the action
  int icon;                  ///< an optional icon ID to use

/// \defgroup ADF_ Action flags
/// used by register_action(). The upper 16 bits are reserved.
//@{
#define ADF_OWN_HANDLER   0x01  ///< handler is owned by the action; it'll be
                                ///< destroyed when the action is unregistered.
                                ///< Use DYNACTION_DESC_LITERAL to set this bit.
#define ADF_NO_UNDO       0x02  ///< the action does not create an undo point.
                                ///< useful for actions that do not modify the database.
#define ADF_OT_MASK       0x0C  ///< Owner type mask
#define ADF_OT_PLUGIN     0x00  ///< Owner is a plugin_t
#define ADF_OT_PLUGMOD    0x04  ///< Owner is a plugmod_t
#define ADF_OT_PROCMOD    0x08  ///< Owner is a procmod_t
#define ADF_GLOBAL        0x10  ///< Register the action globally, so that it's
                                ///< available even if no IDB is present
#define ADF_NO_HIGHLIGHT  0x20  ///< After activating, do not update the highlight
                                ///< according to what's under the cursor (listings only.)
#define ADF_CHECKABLE     0x40  ///< action is checkable
#define ADF_CHECKED       0x80  ///< starts in a checked state (requires ADF_CHECKABLE)
//@}
  int flags;                 ///< See \ref ADF_
};

/// Get an ::action_desc_t instance with the provided plugmod_t as the owner
/// This is meant for plugins
#define ACTION_DESC_LITERAL_PLUGMOD(name, label, handler, plgmod, shortcut, tooltip, icon) \
  { sizeof(action_desc_t), name, label, handler, plgmod, shortcut, tooltip, icon, ADF_OT_PLUGMOD }

/// Get an ::action_desc_t instance with the provided procmod_t as the owner
/// This is meant for processor modules implementing processor_t::ev_get_procmod
#define ACTION_DESC_LITERAL_PROCMOD(name, label, handler, prcmod, shortcut, tooltip, icon) \
  { sizeof(action_desc_t), name, label, handler, prcmod, shortcut, tooltip, icon, ADF_OT_PROCMOD }

/// Get an ::action_desc_t instance with a given owner and flags
#define ACTION_DESC_LITERAL_OWNER(name, label, handler, owner, shortcut, tooltip, icon, flags) \
  { sizeof(action_desc_t), name, label, handler, owner, shortcut, tooltip, icon, flags }

/// For attach_dynamic_action_to_popup() only
#define DYNACTION_DESC_LITERAL(label, handler, shortcut, tooltip, icon) \
  { sizeof(action_desc_t), nullptr, label, handler, nullptr, shortcut, tooltip, icon, ADF_OWN_HANDLER }

/// Codes for getting/setting action attributes
enum action_attr_t
{
  AA_NONE,        ///< no effect
  AA_LABEL,       ///< see update_action_label()
  AA_SHORTCUT,    ///< see update_action_shortcut()
  AA_TOOLTIP,     ///< see update_action_tooltip()
  AA_ICON,        ///< see update_action_icon()
  AA_STATE,       ///< see update_action_state()
  AA_CHECKABLE,   ///< see update_action_checkable()
  AA_CHECKED,     ///< see update_action_checked()
  AA_VISIBILITY,  ///< see update_action_visibility()
};

#ifndef SWIG
// Handlers to be used with create_custom_viewer()
class custom_viewer_handlers_t
{
  int cb;
public:
  custom_viewer_handlers_t(
          custom_viewer_keydown_t *_keyboard = nullptr,
          custom_viewer_popup_t *_popup = nullptr,
          custom_viewer_mouse_moved_t *_mouse_moved = nullptr,
          custom_viewer_click_t *_click = nullptr,
          custom_viewer_dblclick_t *_dblclick = nullptr,
          custom_viewer_curpos_t *_curpos = nullptr,
          custom_viewer_close_t *_close = nullptr,
          custom_viewer_help_t *_help = nullptr,
          custom_viewer_adjust_place_t *_adjust_place = nullptr,
          custom_viewer_get_place_xcoord_t *_get_place_xcoord = nullptr,
          custom_viewer_location_changed_t *_location_changed = nullptr,
          custom_viewer_can_navigate_t *_can_navigate = nullptr)
    : cb(sizeof(*this)),
      keyboard(_keyboard),
      popup(_popup),
      mouse_moved(_mouse_moved),
      click(_click),
      dblclick(_dblclick),
      curpos(_curpos),
      close(_close),
      help(_help),
      adjust_place(_adjust_place),
      get_place_xcoord(_get_place_xcoord),
      location_changed(_location_changed),
      can_navigate(_can_navigate)
  {}
  custom_viewer_keydown_t *keyboard;
  custom_viewer_popup_t *popup;
  custom_viewer_mouse_moved_t *mouse_moved;
  custom_viewer_click_t *click;
  custom_viewer_dblclick_t *dblclick;
  custom_viewer_curpos_t *curpos;
  custom_viewer_close_t *close;
  custom_viewer_help_t *help;
  custom_viewer_adjust_place_t *adjust_place;
  custom_viewer_get_place_xcoord_t *get_place_xcoord;
  custom_viewer_location_changed_t *location_changed;
  custom_viewer_can_navigate_t *can_navigate;
};
#endif // SWIG


#ifndef __UI__         // Not for the UI

// Convenience functions offered by the user interface

/// Execute a list of UI requests (::ui_execute_ui_requests_list).
/// \returns a request id: a unique number that can be used to cancel the request

THREAD_SAFE inline int execute_ui_requests(ui_requests_t *reqs)
{
  return callui(ui_execute_ui_requests_list, reqs).i;
}


/// Execute a variable number of UI requests (::ui_execute_ui_requests).
/// The UI requests will be dispatched in the context of the main thread.
/// \param req  pointer to the first request ,use nullptr to terminate the var arg request list
/// \return a request id: a unique number that can be used to cancel the request

THREAD_SAFE inline int execute_ui_requests(ui_request_t *req, ...)
{
  va_list va;
  va_start(va, req);
  int req_id = callui(ui_execute_ui_requests, req, va).i;
  va_end(va);
  return req_id;
}


/// Try to cancel an asynchronous exec request (::ui_cancel_exec_request).
/// \param req_id  request id
/// \retval true   successfully canceled
/// \retval false  request has already been processed.

THREAD_SAFE inline bool cancel_exec_request(int req_id)
{
  return callui(ui_cancel_exec_request, req_id).cnd;
}


/// Try to cancel asynchronous exec requests created by the specified thread.
/// \param tid  thread id
/// \return number of the canceled requests.

THREAD_SAFE inline int cancel_thread_exec_requests(qthread_t tid)
{
  return callui(ui_cancel_thread_exec_requests, tid).i;
}

/// Get the group of widgets/registers
/// this view is synchronized with
/// \param w the widget
/// \return the group of widgets/registers, or nullptr

inline const synced_group_t *get_synced_group(const TWidget *w)
{
  return (synced_group_t *) callui(ui_get_synced_group, w).vptr;
}

/// Jump to the specified address (::ui_jumpto).
/// \param ea           destination
/// \param opnum        -1: don't change x coord
/// \param uijmp_flags  \ref UIJMP_
/// \return success

inline bool jumpto(ea_t ea, int opnum=-1, int uijmp_flags=UIJMP_ACTIVATE)
{
  return callui(ui_jumpto, ea, opnum, uijmp_flags).cnd;
}


/// Show a banner dialog box (::ui_banner).
/// \param wait  time to wait before closing
/// \retval 1    ok
/// \retval 0    esc was pressed

inline bool banner(int wait)               { return callui(ui_banner, wait).cnd; }


/// Can we use msg() functions?

THREAD_SAFE inline bool is_msg_inited(void) { return callui(ui_is_msg_inited).cnd; }


/// Refresh marked windows (::ui_refreshmarked)

inline void refresh_idaview(void)          { callui(ui_refreshmarked); }


/// Refresh all disassembly views (::ui_refresh), forces an immediate refresh.
/// Please consider request_refresh() instead

inline void refresh_idaview_anyway(void)   { callui(ui_refresh); }


/// Allow the user to set analyzer options. (show a dialog box) (::ui_analyzer_options)

inline void analyzer_options(void)         { callui(ui_analyzer_options); }


/// Get the address at the screen cursor (::ui_screenea)

inline ea_t get_screen_ea(void)            { ea_t ea; callui(ui_screenea, &ea); return ea; }


/// Get current operand number, -1 means no operand (::ui_get_opnum)

inline int get_opnum(void)                 { return callui(ui_get_opnum).i; }


/// Get the cursor position on the screen (::ui_get_cursor).
/// \note coordinates are 0-based
/// \param[out] x  x-coordinate
/// \param[out] y  y-coordinate
/// \retval true   pointers are filled
/// \retval false  no disassembly window open

inline bool get_cursor(int *x, int *y)     { return callui(ui_get_cursor, x, y).cnd; }


/// Get coordinates of the output window's cursor (::ui_get_output_cursor).
/// \note coordinates are 0-based
/// \note this function will succeed even if the output window is not visible
/// \param[out] x   column
/// \param[out] y   line number (global, from the start of output)
/// \retval false   the output window has been destroyed.
/// \retval true    pointers are filled

inline bool get_output_cursor(int *x, int *y) { return callui(ui_get_output_cursor, x, y).cnd; }


/// Get current line from the disassemble window (::ui_get_curline).
/// \return cptr  current line with the color codes
/// (use tag_remove() to remove the color codes)

inline const char *get_curline(void)       { return callui(ui_get_curline).cptr; }


/// Open the given url (::ui_open_url)

inline void open_url(const char *url)      { callui(ui_open_url, url); }


/// Get the current address in a hex view.
/// \param hexdump_num number of hexview window

inline ea_t get_hexdump_ea(int hexdump_num) { ea_t ea; callui(ui_hexdumpea, &ea, hexdump_num); return ea; }


/// Get keyboard key code by its name (::ui_get_key_code)

inline ushort get_key_code(const char *keyname) { return callui(ui_get_key_code, keyname).i16; }


/// Get shortcut code previously created by ::ui_get_key_code.
/// \param key    key constant
/// \param shift  modifiers
/// \param is_qt  are we using gui version?

inline ushort lookup_key_code(int key, int shift, bool is_qt) { return callui(ui_lookup_key_code, key, shift, is_qt).i16; }


/// Refresh navigation band if changed (::ui_refresh_navband).
/// \param force refresh regardless

inline void refresh_navband(bool force)     { callui(ui_refresh_navband, force); }


/// Mark a non-modal custom chooser for a refresh (::ui_refresh_chooser).
/// \param title  title of chooser
/// \return success

inline bool refresh_chooser(const char *title) { return callui(ui_refresh_chooser, title).cnd; }


/// Close a non-modal chooser (::ui_close_chooser).
/// \param title window title of chooser to close
/// \return success

inline bool close_chooser(const char *title) { return callui(ui_close_chooser, title).cnd; }


/// Install command line interpreter (::ui_install_cli)

inline void install_command_interpreter(const cli_t *cp) { callui(ui_install_cli, cp, true); }


/// Remove command line interpreter (::ui_install_cli)

inline void remove_command_interpreter(const cli_t *cp) { callui(ui_install_cli, cp, false); }


/// Generate disassembly text for a range.
/// \param[out] text  result
/// \param ea1        start address
/// \param ea2        end address
/// \param truncate_lines  (on idainfo::margin)

inline void gen_disasm_text(text_t &text, ea_t ea1, ea_t ea2, bool truncate_lines) { callui(ui_gen_disasm_text, &text, ea1, ea2, truncate_lines); }


/// Execute code in the main thread.
/// \param req   request specifying the code to execute
/// \param reqf  \ref MFF_
/// \return if \ref #MFF_NOWAIT is specified, return the request id.
///         otherwise return the value returned by exec_request_t::execute().

THREAD_SAFE inline int execute_sync(exec_request_t &req, int reqf) { return callui(ui_execute_sync, &req, reqf).i; }


/// Set the docking position of a widget (::ui_set_dock_pos).
/// \param src_ctrl                title of widget to dock
/// \param dest_ctrl               where to dock: if nullptr or invalid then create
///                                a new tab relative to current active tab
/// \param orient                  \ref DP_
/// \param left,top,right,bottom   dimensions of dock, if not specified or invalid then
///                                create the widget in the center of the screen with the
///                                default size
/// \return success

inline bool set_dock_pos(const char *src_ctrl, const char *dest_ctrl, int orient, int left = 0, int top = 0, int right = 0, int bottom = 0)
{
  return callui(ui_set_dock_pos, src_ctrl, dest_ctrl, orient, left, top, right, bottom).cnd;
}


/// Load an icon from a file (::ui_load_custom_icon_file).
/// Also see load_custom_icon(const void *, unsigned int, const char *)
/// \param file_name path  to file
/// \return icon id

inline int load_custom_icon(const char *file_name) { return callui(ui_load_custom_icon_file, file_name).i; }


/// Load an icon and return its id (::ui_load_custom_icon).
/// \param ptr     pointer to raw image data
/// \param len     image data length
/// \param format  image format
/// \return icon id

inline int load_custom_icon(const void *ptr, unsigned int len, const char *format) { return callui(ui_load_custom_icon, ptr, len, format).i; }


/// Free an icon loaded with load_custom_icon() (::ui_free_custom_icon).

inline void free_custom_icon(int icon_id) { callui(ui_free_custom_icon, icon_id); }


/// Processes a UI action by name.
/// \param name   action name
/// \param flags  reserved/not used
/// \param param  reserved/not used

inline bool process_ui_action(const char *name, int flags=0, void *param=nullptr)
{
  return callui(ui_process_action, name, flags, param).cnd;
}


/// Take a database snapshot (::ui_take_database_snapshot).
/// \param ss       in/out parameter.
///                   - in: description, flags
///                   - out: filename, id
/// \param err_msg  optional error msg buffer
/// \return success

inline bool take_database_snapshot(
        snapshot_t *ss,
        qstring *err_msg)
{
  return callui(ui_take_database_snapshot, ss, err_msg).cnd;
}


/// Restore a database snapshot.
/// Note: This call is asynchronous. When it is completed, the callback will be triggered.
/// \param ss  snapshot instance (see build_snapshot_tree())
/// \param cb  A callback that will be triggered with a nullptr string.
///             on success and an actual error message on failure.
/// \param ud  user data passed to be passed to the callback
/// \return false if restoration could not be started (snapshot file was not found).  \n
///         If the returned value is True then check if the operation succeeded from the callback.

inline bool restore_database_snapshot(
        const snapshot_t *ss,
        ss_restore_cb_t *cb,
        void *ud)
{
  return callui(ui_restore_database_snapshot, ss, cb, ud).cnd;
}

/// Timer opaque handle
typedef struct __qtimer_t {} *qtimer_t;


/// Register a timer (::ui_register_timer).
/// Timer functions are thread-safe and the callback is executed
/// in the context of the main thread.
/// \param interval_ms  interval in milliseconds
/// \param callback     the callback can return -1 to unregister the timer;
///                     any other value >= 0 defines the new interval for the timer
/// \param ud callback  params
/// \return handle to registered timer (use this handle to unregister it), or nullptr

THREAD_SAFE inline qtimer_t register_timer(
        int interval_ms,
        int (idaapi *callback)(void *ud),
        void *ud)
{
  return (qtimer_t)(callui(ui_register_timer, interval_ms, callback, ud).vptr);
}


/// Unregister a timer (::ui_unregister_timer).
/// \param t handle to a registered timer
/// \return success

THREAD_SAFE inline bool unregister_timer(qtimer_t t)
{
  return callui(ui_unregister_timer, t).cnd;
}

//-------------------------------------------------------------------------

/// Create a new action (::ui_register_action).
/// After an action has been created, it is possible to attach it
/// to menu items (attach_action_to_menu()), or to popup menus
/// (attach_action_to_popup()).
///
/// Because the actions will need to call the handler's activate() and
/// update() methods at any time, you shouldn't build your action handler
/// on the stack.
///
/// Please see the SDK's "ht_view" plugin for an example how
/// to register actions.
/// \param desc action to register
/// \return success

inline bool register_action(const action_desc_t &desc)
{
  return callui(ui_register_action, &desc).cnd;
}


/// Delete a previously-registered action (::ui_unregister_action).
/// \param name  name of action
/// \return success

inline bool unregister_action(const char *name)
{
  return callui(ui_unregister_action, name).cnd;
}


/// Get a list of all currently-registered actions
/// \param out the list of actions to be filled
inline void get_registered_actions(qstrvec_t *out)
{
  callui(ui_get_registered_actions, out);
}


/// Create a toolbar with the given name, label and optional position
/// \param name name of toolbar (must be unique)
/// \param label label of toolbar
/// \param before if non-nullptr, the toolbar before which the new toolbar will be inserted
/// \param flags a combination of \ref CREATETB_, to determine toolbar position
/// \return success
inline bool create_toolbar(
        const char *name,
        const char *label,
        const char *before = nullptr,
        int flags = 0)
{
  return callui(ui_create_toolbar, name, label, before, flags).cnd;
}


/// Delete an existing toolbar
/// \param name name of toolbar
/// \return success
inline bool delete_toolbar(const char *name)
{
  return callui(ui_delete_toolbar, name).cnd;
}


/// Create a menu with the given name, label and optional position,
/// either in the menubar, or as a submenu.
/// If 'menupath' is non-nullptr, it provides information about where
/// the menu should be positioned.
/// First, IDA will try and resolve the corresponding menu by its name.
/// If such an existing menu is found and is present in the menubar,
/// then the new menu will be inserted in the menubar before it.
/// Otherwise, IDA will try to resolve 'menupath' as it would for
/// attach_action_to_menu() and, if found, add the new menu like so:
/// \code
///   // The new 'My menu' submenu will appear in the 'Comments' submenu
///   // before the 'Enter comment..." command
///   create_menu("(...)", "My menu", "Edit/Comments/Enter comment...");
/// \endcode
/// or
/// \code
///   // The new 'My menu' submenu will appear at the end of the
///   // 'Comments' submenu.
///   create_menu("(...)", "My menu", "Edit/Comments/");
/// \endcode
/// If the above fails, the new menu will be appended to the menubar.
/// \param name name of menu (must be unique)
/// \param label label of menu
/// \param menupath where should the menu be inserted
/// \return success
inline bool create_menu(
        const char *name,
        const char *label,
        const char *menupath=nullptr)
{
  return callui(ui_create_menu, name, label, menupath).cnd;
}


/// Delete an existing menu
/// \param name name of menu
/// \return success
inline bool delete_menu(const char *name)
{
  return callui(ui_delete_menu, name).cnd;
}


/// Attach a previously-registered action to the menu (::ui_attach_action_to_menu).
/// \note You should not change top level menu, or the Edit,Plugins submenus
/// If you want to modify the debugger menu, do it at the ui_debugger_menu_change
/// event (ida might destroy your menu item if you do it elsewhere).
/// \param menupath  path to the menu item after or before which the insertion will take place.  \n
///                    - Example: Debug/StartProcess
///                    - Whitespace, punctuation are ignored.
///                    - It is allowed to specify only the prefix of the menu item.
///                    - Comparison is case insensitive.
///                    - menupath may start with the following prefixes:
///                    - [S] - modify the main menu of the structure window
///                    - [E] - modify the main menu of the enum window
/// \param name      the action name
/// \param flags     a combination of \ref SETMENU_, to determine menu item position
/// \return success

inline bool attach_action_to_menu(
        const char *menupath,
        const char *name,
        int flags=0)
{
  return callui(ui_attach_action_to_menu, menupath, name, flags).cnd;
}


/// Detach an action from the menu (::ui_detach_action_from_menu).
/// \param menupath   path to the menu item
/// \param name       the action name
/// \return success

inline bool detach_action_from_menu(
        const char *menupath,
        const char *name)
{
  return callui(ui_detach_action_from_menu, menupath, name).cnd;
}


/// Attach an action to an existing toolbar (::ui_attach_action_to_toolbar).
/// \param toolbar_name  the name of the toolbar
/// \param name          the action name
/// \return success

inline bool attach_action_to_toolbar(
        const char *toolbar_name,
        const char *name)
{
  return callui(ui_attach_action_to_toolbar, toolbar_name, name).cnd;
}


/// Detach an action from the toolbar (::ui_detach_action_from_toolbar).
/// \param toolbar_name  the name of the toolbar
/// \param name          the action name
/// \return success

inline bool detach_action_from_toolbar(
        const char *toolbar_name,
        const char *name)
{
  return callui(ui_detach_action_from_toolbar, toolbar_name, name).cnd;
}


/// Helper.
///
/// You are not encouraged to use this, as it mixes flags for
/// both register_action(), and attach_action_to_menu().
///
/// The only reason for its existence is to make it simpler
/// to port existing plugins to the new actions API.

inline bool register_and_attach_to_menu(
        const char *menupath,
        const char *name,
        const char *label,
        const char *shortcut,
        int flags,
        action_handler_t *handler,
        void *owner,
        int action_desc_t_flags)
{
  action_desc_t desc = ACTION_DESC_LITERAL_OWNER(name, label, handler, owner, shortcut, nullptr, -1, action_desc_t_flags);
  if ( !register_action(desc) )
    return false;
  if ( !attach_action_to_menu(menupath, name, (flags & SETMENU_POSMASK)) )
  {
    unregister_action(name);
    return false;
  }
  return true;
}

//------------------------------------------------------------------------
// Get VCL global variables
class TPopupMenu;

/// Display a widget, dock it if not done before
/// \param widget    widget to display
/// \param options   \ref WIDGET_OPEN
/// \param dest_ctrl where to dock: if nullptr or invalid then
///                  use the active docker if there is not
///                  create a new tab relative to current active tab

inline void display_widget(TWidget *widget, uint32 options, const char *dest_ctrl=nullptr)
{
  callui(ui_display_widget, widget, options, dest_ctrl);
}


/// Close widget (::ui_close_widget, only gui version).
/// \param widget   pointer to the widget to close
/// \param options  \ref WIDGET_CLOSE

inline void close_widget(TWidget *widget, int options)
{
  callui(ui_close_widget, widget, options);
}


/// Activate widget (only gui version) (::ui_activate_widget).
/// \param widget      existing widget to display
/// \param take_focus  give focus to given widget

inline void activate_widget(TWidget *widget, bool take_focus)
{
  callui(ui_activate_widget, widget, take_focus);
}


/// Find widget with the specified caption (only gui version) (::ui_find_widget).
/// NB: this callback works only with the tabbed widgets!
/// \param caption  title of tab, or window title if widget is not tabbed
/// \return pointer to the TWidget, nullptr if none is found

inline TWidget *find_widget(const char *caption)
{
  return (TWidget *) callui(ui_find_widget, caption).vptr;
}


/// Get a pointer to the current widget (::ui_get_current_widget).

inline TWidget *get_current_widget(void)
{
  return (TWidget *) callui(ui_get_current_widget).vptr;
}


/// Get the type of the TWidget * (::ui_get_widget_type).

inline twidget_type_t get_widget_type(TWidget *widget)
{
  return twidget_type_t(callui(ui_get_widget_type, widget).i);
}


/// Get the TWidget's title (::ui_get_widget_title).

inline bool get_widget_title(qstring *buf, TWidget *widget)
{
  return callui(ui_get_widget_title, buf, widget).cnd;
}

/// Create new ida viewer based on ::place_t (::ui_create_custom_viewer).
/// \param title     name of viewer
/// \param minplace  first location of the viewer
/// \param maxplace  last location of the viewer
/// \param curplace  set current location
/// \param rinfo     renderer information (can be nullptr)
/// \param ud        user data for the viewer
/// \param cvhandlers    handlers for the viewer (can be nullptr)
/// \param cvhandlers_ud pointer to arbitrary user data; it will be passed to cvhandlers
/// \param parent    widget to hold viewer
/// \return pointer to resulting viewer

inline TWidget *create_custom_viewer(
        const char *title,
        const place_t *minplace,
        const place_t *maxplace,
        const place_t *curplace,
        const renderer_info_t *rinfo,
        void *ud,
        const custom_viewer_handlers_t *cvhandlers,
        void *cvhandlers_ud,
        TWidget *parent = nullptr)
{
  return (TWidget*) callui(
          ui_create_custom_viewer, title, minplace,
          maxplace, curplace, rinfo, ud, cvhandlers, cvhandlers_ud, parent).vptr;
}


/// Append 'loc' to the viewer's history, and cause the viewer
/// to display it.
///< \param v     (TWidget *)
///< \param loc   (const lochist_entry_t &)
///< \param flags (uint32) or'ed combination of CVNF_* values
///< \return success

inline bool custom_viewer_jump(
        TWidget *v,
        const lochist_entry_t &loc,
        uint32 flags=0)
{
  return callui(ui_custom_viewer_jump, v, &loc, flags).cnd;
}


/// Push current location in the history and jump to the given location (::ui_ea_viewer_history_push_and_jump).
/// This will jump in the given ea viewer and also in other synchronized views.
/// \param v      ea viewer
/// \param ea     jump destination
/// \param x,y    coords on screen
/// \param lnnum  desired line number of given address

inline bool ea_viewer_history_push_and_jump(TWidget *v, ea_t ea, int x, int y, int lnnum)
{
  return callui(ui_ea_viewer_history_push_and_jump, v, ea, x, y, lnnum).cnd;
}


/// Get information about what's in the history (::ui_ea_viewer_history_info).
/// \param[out] nback  number of available back steps
/// \param[out] nfwd   number of available forward steps
/// \param v           ea viewer
/// \retval false  if the given ea viewer does not exist
/// \retval true   otherwise

inline bool get_ea_viewer_history_info(int *nback, int *nfwd, TWidget *v)
{
  return callui(ui_ea_viewer_history_info, nback, nfwd, v).cnd;
}


/// Refresh custom ida viewer (::ui_refresh_custom_viewer)

inline void refresh_custom_viewer(TWidget *custom_viewer)
{
  callui(ui_refresh_custom_viewer, custom_viewer);
}


/// Repaint the given widget immediately (::ui_repaint_qwidget)

inline void repaint_custom_viewer(TWidget *custom_viewer)
{
  callui(ui_repaint_qwidget, custom_viewer);
}


/// Destroy custom ida viewer

inline void destroy_custom_viewer(TWidget *custom_viewer)
{
  callui(ui_destroy_custom_viewer, custom_viewer);
}


/// Set cursor position in custom ida viewer.
/// \param custom_viewer view
/// \param place target position
/// \param x desired cursor position (column)
/// \param y desired cursor position (line)
/// \return success

inline bool jumpto(TWidget *custom_viewer, place_t *place, int x, int y)
{
  return callui(ui_jump_in_custom_viewer, custom_viewer, place, x, y).cnd;
}


/// Get current place in a custom viewer (::ui_get_curplace).
///
/// See also the more complete get_custom_viewer_location()
///
/// \param custom_viewer  view
/// \param mouse          mouse position (otherwise cursor position)
/// \param[out] x         x coordinate
/// \param[out] y         y coordinate

inline place_t *get_custom_viewer_place(
        TWidget *custom_viewer,
        bool mouse,
        int *x,
        int *y)
{
  return (place_t *)callui(ui_get_curplace, custom_viewer, mouse, x, y).vptr;
}


/// Get the current location in a custom viewer (::ui_get_custom_viewer_location).
inline bool get_custom_viewer_location(
        lochist_entry_t *out,
        TWidget *custom_viewer,
        bool mouse=false)
{
  return callui(ui_get_custom_viewer_location, out, custom_viewer, mouse).cnd;
}

/// Are we running inside IDA Qt?

inline bool is_idaq()
{
  return callui(ui_is_idaq).cnd;
}


/// Insert a previously-registered action into the widget's popup menu (::ui_attach_action_to_popup).
/// This function has two "modes": 'single-shot', and 'permanent'.
/// \param widget        target widget
/// \param popup_handle  target popup menu
///                        - if non-nullptr, the action is added to this popup
///                          menu invocation (i.e., 'single-shot')
///                        - if nullptr, the action is added to a list of actions
///                          that should always be present in context menus for this widget
///                          (i.e., 'permanent'.)
/// \param name          action name
/// \param popuppath     can be nullptr
/// \param flags         a combination of SETMENU_ flags (see \ref SETMENU_)
/// \return success

inline bool attach_action_to_popup(
        TWidget *widget,
        TPopupMenu *popup_handle,
        const char *name,
        const char *popuppath = nullptr,
        int flags=0)
{
  return callui(ui_attach_action_to_popup, widget, popup_handle, name, popuppath, flags).cnd;
}


/// Remove a previously-registered action, from the list of 'permanent'
/// context menu actions for this widget (::ui_detach_action_from_popup).
/// This only makes sense if the action has been added to 'widget's list
/// of permanent popup actions by calling attach_action_to_popup
/// in 'permanent' mode.
/// \param widget  target widget
/// \param name    action name

inline bool detach_action_from_popup(TWidget *widget, const char *name)
{
  return callui(ui_detach_action_from_popup, widget, name).cnd;
}


/// Create & insert an action into the widget's popup menu (::ui_attach_dynamic_action_to_popup).
/// \note action_desc_t::handler for 'desc' must be instantiated using 'new', as it
/// will be 'delete'd when the action is unregistered.
/// \param unused        deprecated; should be nullptr
/// \param popup_handle  target popup
/// \param desc          created with #DYNACTION_DESC_LITERAL
/// \param popuppath     can be nullptr
/// \param flags         a combination of SETMENU_ constants (see \ref SETMENU_)
/// \param buf           a buffer, to retrieve the generated action name - can be nullptr
/// \return success

inline bool attach_dynamic_action_to_popup(
        TWidget *unused,
        TPopupMenu *popup_handle,
        const action_desc_t &desc,
        const char *popuppath = nullptr,
        int flags = 0,
        qstring *buf = nullptr)
{
  return callui(ui_attach_dynamic_action_to_popup, unused,
                popup_handle, &desc, popuppath, flags, buf).cnd;
}

/// \defgroup ui_uaa_funcs Functions: update actions
/// Convenience functions for ::ui_update_action_attr
//@{

/// Update an action's label (::ui_update_action_attr).
/// \param name   action name
/// \param label  new label
/// \return success

inline bool update_action_label(const char *name, const char *label)
{
  return callui(ui_update_action_attr, name, AA_LABEL, label).cnd;
}


/// Update an action's shortcut (::ui_update_action_attr).
/// \param name      action name
/// \param shortcut  new shortcut
/// \return success

inline bool update_action_shortcut(const char *name, const char *shortcut)
{
  return callui(ui_update_action_attr, name, AA_SHORTCUT, shortcut).cnd;
}


/// Update an action's tooltip (::ui_update_action_attr).
/// \param name     action name
/// \param tooltip  new tooltip
/// \return success

inline bool update_action_tooltip(const char *name, const char *tooltip)
{
  return callui(ui_update_action_attr, name, AA_TOOLTIP, tooltip).cnd;
}


/// Update an action's icon (::ui_update_action_attr).
/// \param name  action name
/// \param icon  new icon id
/// \return success

inline bool update_action_icon(const char *name, int icon)
{
  return callui(ui_update_action_attr, name, AA_ICON, &icon).cnd;
}


/// Update an action's state (::ui_update_action_attr).
/// \param name   action name
/// \param state  new state
/// \return success

inline bool update_action_state(const char *name, action_state_t state)
{
  return callui(ui_update_action_attr, name, AA_STATE, &state).cnd;
}


/// Update an action's checkability (::ui_update_action_attr).
/// \param name       action name
/// \param checkable  new checkability
/// \return success

inline bool update_action_checkable(const char *name, bool checkable)
{
  return callui(ui_update_action_attr, name, AA_CHECKABLE, &checkable).cnd;
}


/// Update an action's checked state (::ui_update_action_attr).
/// \param name     action name
/// \param checked  new checked state
/// \return success

inline bool update_action_checked(const char *name, bool checked)
{
  return callui(ui_update_action_attr, name, AA_CHECKED, &checked).cnd;
}


/// Update an action's visibility (::ui_update_action_attr).
/// \param name     action name
/// \param visible  new visibility
/// \return success

inline bool update_action_visibility(const char *name, bool visible)
{
  return callui(ui_update_action_attr, name, AA_VISIBILITY, &visible).cnd;
}

//@}

/// \defgroup ui_gaa_funcs Functions: get action attributes
/// Convenience functions for ::ui_get_action_attr
//{

/// Get an action's label (::ui_get_action_attr).
/// \param[out] label  the action label
/// \param name        the action name
/// \return success

inline bool get_action_label(qstring *label, const char *name)
{
  return callui(ui_get_action_attr, name, AA_LABEL, label).cnd;
}


/// Get an action's shortcut (::ui_get_action_attr).
/// \param[out] shortcut  the action shortcut
/// \param name           the action name
/// \return success

inline bool get_action_shortcut(qstring *shortcut, const char *name)
{
  return callui(ui_get_action_attr, name, AA_SHORTCUT, shortcut).cnd;
}


/// Get an action's tooltip (::ui_get_action_attr).
/// \param[out] tooltip  the action tooltip
/// \param name          the action name
/// \return success

inline bool get_action_tooltip(qstring *tooltip, const char *name)
{
  return callui(ui_get_action_attr, name, AA_TOOLTIP, tooltip).cnd;
}


/// Get an action's icon (::ui_get_action_attr).
/// \param name       the action name
/// \param[out] icon  the icon id
/// \return success

inline bool get_action_icon(const char *name, int *icon)
{
  return callui(ui_get_action_attr, name, AA_ICON, icon).cnd;
}


/// Get an action's state (::ui_get_action_attr).
/// \param name        the action name
/// \param[out] state  the action's state
/// \return success

inline bool get_action_state(const char *name, action_state_t *state)
{
  return callui(ui_get_action_attr, name, AA_STATE, state).cnd;
}


/// Get an action's checkability (::ui_get_action_attr).
/// \param name            the action name
/// \param[out] checkable  the action's checkability
/// \return success

inline bool get_action_checkable(const char *name, bool *checkable)
{
  return callui(ui_get_action_attr, name, AA_CHECKABLE, checkable).cnd;
}


/// Get an action's checked state (::ui_get_action_attr).
/// \param name          the action name
/// \param[out] checked  the action's checked state
/// \return success

inline bool get_action_checked(const char *name, bool *checked)
{
  return callui(ui_get_action_attr, name, AA_CHECKED, checked).cnd;
}


/// Get an action's visibility (::ui_get_action_attr).
/// \param name             the action name
/// \param[out] visibility  the action's visibility
/// \return success

inline bool get_action_visibility(const char *name, bool *visibility)
{
  return callui(ui_get_action_attr, name, AA_VISIBILITY, visibility).cnd;
}

//@}

/// \defgroup ui_scvh_funcs Functions: custom viewer handlers
/// Convenience functions for ::ui_set_custom_viewer_handler
//@{

/// Set handlers for custom viewer events
/// Any of these handlers may be nullptr

inline void set_custom_viewer_handlers(
        TWidget *custom_viewer,
        const custom_viewer_handlers_t *cvh,
        void *cvh_ud)
{
  callui(ui_set_custom_viewer_handlers, custom_viewer, cvh, cvh_ud);
}


/// Set a handler for a custom viewer event (::ui_set_custom_viewer_handler).
/// see also ::ui_set_custom_viewer_handlers
/// \param custom_viewer    the custom viewer
/// \param handler_id       one of CVH_ in ::custom_viewer_handler_id_t
/// \param handler_or_data  can be a handler or data. see examples in \ref ui_scvh_funcs
/// \return old value of the handler or data

inline void *set_custom_viewer_handler(
        TWidget *custom_viewer,
        custom_viewer_handler_id_t handler_id,
        void *handler_or_data)
{
  return callui(ui_set_custom_viewer_handler, custom_viewer, handler_id,
                handler_or_data).vptr;
}


/// Allow the given viewer to interpret Qt events (::ui_set_custom_viewer_handler)

inline bool set_custom_viewer_qt_aware(TWidget *custom_viewer)
{
  return callui(ui_set_custom_viewer_handler, custom_viewer, CVH_QT_AWARE).cnd;
}

//@}


/// Get current line of custom viewer (::ui_get_custom_viewer_curline).
/// The returned line contains color codes
/// \param custom_viewer  view
/// \param mouse          mouse position (otherwise cursor position)
/// \return pointer to contents of current line

inline const char *get_custom_viewer_curline(TWidget *custom_viewer, bool mouse)
{
  return callui(ui_get_custom_viewer_curline, custom_viewer, mouse).cptr;
}


/// Get the X position of the item, in the line
/// \param custom_viewer the widget
/// \param pline a place corresponding to the line
/// \param pitem a place corresponding to the item
/// \return -1 if 'pitem' is not included in the line
/// \return -2 if 'pitem' points at the entire line
/// \return >= 0 for the X coordinate within the pline, where pitem points

inline int get_custom_viewer_place_xcoord(
        TWidget *custom_viewer,
        const place_t *pline,
        const place_t *pitem)
{
  return callui(ui_get_custom_viewer_place_xcoord, custom_viewer, pline, pitem).i;
}


/// Get the current user input event (mouse button press,
/// key press, ...)
/// It is sometimes desirable to be able to tell when a certain
/// situation happens (e.g., 'view_curpos' gets triggered); this
/// function exists to provide that context (GUI version only)
/// \param out the input event data
/// \return false if we are not currently processing a user input event

inline bool get_user_input_event(
        input_event_t *out)
{
  return callui(ui_get_user_input_event, out).cnd;
}

/// Get current line of output window (::ui_get_output_curline).
/// \param buf      output buffer
/// \param mouse    current for mouse pointer?
/// \return false if output contains no text

inline bool get_output_curline(qstring *buf, bool mouse)
{
  return callui(ui_get_output_curline, buf, mouse).cnd;
}


/// Returns selected text from output window (::ui_get_output_selected_text).
/// \param buf      output buffer
/// \return true if there is a selection

inline bool get_output_selected_text(qstring *buf)
{
  return callui(ui_get_output_selected_text, buf).cnd;
}


/// Get current ida viewer (idaview or custom viewer) (::ui_get_current_viewer)

inline TWidget *get_current_viewer(void)
{
  return (TWidget *)callui(ui_get_current_viewer).vptr;
}


/// Get the type of renderer currently in use in the given view (::ui_get_renderer_type)

inline tcc_renderer_type_t get_view_renderer_type(TWidget *v)
{
  return tcc_renderer_type_t(callui(ui_get_renderer_type, v).i);
}


/// Set the type of renderer to use in a view (::ui_set_renderer_type)

inline void set_view_renderer_type(TWidget *v, tcc_renderer_type_t rt)
{
  callui(ui_set_renderer_type, v, rt);
}


/// Set position range for custom viewer (::ui_set_custom_viewer_range)

inline void set_custom_viewer_range(
        TWidget *custom_viewer,
        const place_t *minplace,
        const place_t *maxplace)
{
  callui(ui_set_custom_viewer_range, custom_viewer, minplace, maxplace);
}


/// Create an empty widget, serving as a container for custom
/// user widgets

inline TWidget *create_empty_widget(const char *title, int icon = -1)
{
  return (TWidget *) callui(ui_create_empty_widget, title, icon).vptr;
}


/// Clear the "Output" window

inline void msg_clear()
{
  callui(ui_msg_clear);
}


/// Save the "Output" window contents into a file
/// \param path The path of the file to save the contents into.
///             An empty path means that the user will be prompted for
///             the destination and, if the file already exists, the user
///             will be asked to confirm before overriding its contents.
///             Upon return, 'path' will contain the path that the user
///             chose.
/// \return success

inline bool msg_save(qstring &path)
{
  return callui(ui_msg_save, &path).cnd;
}


/// Retrieve the last 'count' lines from the output window, in reverse
/// order (from most recent, to least recent)
/// \param out Output storage
/// \param count The number of lines to retrieve. -1 means: all

inline void msg_get_lines(qstrvec_t *out, int count=-1)
{
  callui(ui_msg_get_lines, out, count);
}


/// Get the current, active modal TWidget instance.
/// Note that in this context, the "wait dialog" is not considered:
/// this function will return nullptr even if it is currently shown.
/// \return TWidget * the active modal widget, or nullptr

inline TWidget *get_active_modal_widget(void)
{
  return (TWidget *) callui(ui_get_active_modal_widget).vptr;
}


/// Translate the provided ea_t, into its pixel position (plus pixel ranges)
/// on the navigation band.

inline int get_navband_pixel(bool *out_is_vertical, ea_t ea)
{
  return callui(ui_navband_pixel, out_is_vertical, ea).i;
}


/// Translate the pixel position on the navigation band, into an address

inline ea_t get_navband_ea(int pixel)
{
  ea_t ea = BADADDR;
  callui(ui_navband_ea, &ea, pixel);
  return ea;
}


/// Get the system-specific window ID (GUI version only)
/// \param name name of the window (nullptr means the main IDA window)
/// \return the low-level window ID

inline void *get_window_id(const char *name=nullptr)
{
  return callui(ui_get_window_id, name).vptr;
}


/// Is the given custom view an idaview? (::ui_is_idaview)

inline bool is_idaview(TWidget *v)
{
  return callui(ui_is_idaview, v).cnd;
}


/// Get the selected range boundaries (::ui_read_selection).
/// \param v        view
/// \param[out] p1  start of selection
/// \param[out] p2  end of selection
/// \retval false   no range is selected
/// \retval true    ok, start and end are filled

inline bool read_selection(TWidget *v, twinpos_t *p1, twinpos_t *p2)
{
  return callui(ui_read_selection, v, p1, p2).cnd;
}


/// Get the address range for the selected range boundaries,
/// this is the convenient function for read_selection()
/// \param v        view, nullptr means the last active window
///                 containing addresses
/// \param[out] ea1 start ea
/// \param[out] ea2 end ea
/// \retval 0 no range is selected \n
/// \retval 1 ok, start ea and end ea are filled

inline bool read_range_selection(TWidget *v, ea_t *ea1, ea_t *ea2)
{
  return callui(ui_read_range_selection, v, ea1, ea2).cnd;
}


/// Unmark selection (::ui_unmarksel)

inline void unmark_selection(void)         { callui(ui_unmarksel); }


/// Create a code viewer (::ui_create_code_viewer).
/// A code viewer contains on the left side a widget representing the
/// line numbers, and on the right side, the child widget passed as
/// parameter.
/// It will inherit its title from the child widget.
///
/// \param custview  the custom view to be added
/// \param flags     \ref CDVF_
/// \param parent    widget to contain the new code viewer

inline TWidget *create_code_viewer(
        TWidget *custview,
        int flags = 0,
        TWidget *parent = nullptr)
{
  return (TWidget*)callui(ui_create_code_viewer, custview, flags, parent).vptr;
}


/// Set a handler for a code viewer event (::ui_set_custom_viewer_handler). \ingroup ui_scvh_funcs
/// \param code_viewer      the code viewer
/// \param handler_id       one of CDVH_ in ::custom_viewer_handler_id_t
/// \param handler_or_data  can be a handler or data. see examples in \ref ui_scvh_funcs
/// \return old value of the handler or data

inline void *set_code_viewer_handler(
        TWidget *code_viewer,
        custom_viewer_handler_id_t handler_id,
        void *handler_or_data)
{
  return callui(ui_set_custom_viewer_handler, code_viewer, handler_id,
                handler_or_data).vptr;
}


/// Set the user data on a code viewer (::ui_set_custom_viewer_handler). \ingroup ui_scvh_funcs

inline bool set_code_viewer_user_data(TWidget *code_viewer, void *ud)
{
  return callui(ui_set_custom_viewer_handler, code_viewer, CDVH_USERDATA, ud).cnd;
}


/// Get the user data from a custom viewer (::ui_get_viewer_user_data)

inline void *get_viewer_user_data(TWidget *viewer)
{
  return callui(ui_get_viewer_user_data, viewer).vptr;
}


/// Get the type of ::place_t instances a viewer uses & creates (::ui_get_viewer_place_type).

inline tcc_place_type_t get_viewer_place_type(TWidget *viewer)
{
  return tcc_place_type_t(callui(ui_get_viewer_place_type, viewer).i);
}


/// Set handlers for code viewer line events.
/// Any of these handlers may be nullptr

inline void set_code_viewer_line_handlers(
        TWidget *code_viewer,
        code_viewer_lines_click_t *click_handler,
        code_viewer_lines_click_t *popup_handler,
        code_viewer_lines_click_t *dblclick_handler,
        code_viewer_lines_icon_t *drawicon_handler,
        code_viewer_lines_linenum_t *linenum_handler)
{
  callui(ui_set_code_viewer_line_handlers, code_viewer, click_handler,
         popup_handler, dblclick_handler, drawicon_handler, linenum_handler);
}


/// Set space allowed for icons in the margin of a code viewer (::ui_set_custom_viewer_handler). \ingroup ui_scvh_funcs

inline bool set_code_viewer_lines_icon_margin(TWidget *code_viewer, int margin)
{
  return callui(ui_set_custom_viewer_handler, code_viewer, CDVH_LINES_ICONMARGIN, margin).cnd;
}


/// Set alignment for lines in a code viewer (::ui_set_custom_viewer_handler). \ingroup ui_scvh_funcs

inline bool set_code_viewer_lines_alignment(TWidget *code_viewer, int align)
{
  return callui(ui_set_custom_viewer_handler, code_viewer, CDVH_LINES_ALIGNMENT, align).cnd;
}


/// Set radix for values displayed in a code viewer (::ui_set_custom_viewer_handler). \ingroup ui_scvh_funcs

inline bool set_code_viewer_lines_radix(TWidget *code_viewer, int radix)
{
  return callui(ui_set_custom_viewer_handler, code_viewer, CDVH_LINES_RADIX, radix).cnd;
}


/// Specify that the given code viewer is used to display source code (::ui_set_custom_viewer_handler). \ingroup ui_scvh_funcs

inline bool set_code_viewer_is_source(TWidget *code_viewer)
{
  return callui(ui_set_custom_viewer_handler, code_viewer, CDVH_SRCVIEW).cnd;
}


/// Get the size of a tab in spaces (::ui_get_tab_size).
/// \param path  the path of the source view for which the tab size is requested.
///                - if nullptr, the default size is returned.

inline int get_tab_size(const char *path)
{
  return callui(ui_get_tab_size, path).i;
}


/// Clear "Cancelled" flag (::ui_clr_cancelled)

THREAD_SAFE inline void clr_cancelled(void) { callui(ui_clr_cancelled); }


/// Set "Cancelled" flag (::ui_set_cancelled)

THREAD_SAFE inline void set_cancelled(void) { callui(ui_set_cancelled); }


/// Test the ctrl-break flag (::ui_test_cancelled).
/// \retval 1  Ctrl-Break is detected, a message is displayed
/// \retval 2  Ctrl-Break is detected again, a message is not displayed
/// \retval 0  Ctrl-Break is not detected

THREAD_SAFE inline bool user_cancelled(void) { return callui(ui_test_cancelled).cnd; }


/// Display a load file dialog and load file (::ui_load_file).
/// \param[out]    temp_file  name of the file with the extracted archive member.
/// \param[in,out] filename   the name of input file as is,
///                           library or archive name
/// \param[in,out] pli        loader input source,
///                           may be changed to point to temp_file
/// \param neflags            combination of NEF_... bits (see \ref NEF_)
/// \param[in,out] ploaders   list of loaders which accept file,
///                           may be changed for loaders of temp_file
/// \retval true     file was successfully loaded
/// \retval false    otherwise

inline bool ui_load_new_file(
        qstring *temp_file,
        qstring *filename,
        linput_t **pli,
        ushort neflags,
        load_info_t **ploaders)
{
  return callui(ui_load_file, temp_file, filename, pli, neflags, ploaders).cnd;
}


/// Load a debugger plugin and run the specified program (::ui_run_dbg).
/// \param dbgopts  value of the -r command line switch
/// \param exename  name of the file to run
/// \param argc     number of arguments for the executable
/// \param argv     argument vector
/// \return success

inline bool ui_run_debugger(
        const char *dbgopts,
        const char *exename,
        int argc,
        const char *const *argv)
{
  return callui(ui_run_dbg, dbgopts, exename, argc, argv).cnd;
}


/// Load debugging information from a file.
/// \param path     path to file
/// \param li       loader input. if nullptr, check DBG_NAME_KEY
/// \param base     loading address
/// \param verbose  dump status to message window

inline bool load_dbg_dbginfo(
        const char *path,
        linput_t *li=nullptr,
        ea_t base=BADADDR,
        bool verbose=false)
{
  return callui(ui_dbg_load_dbg_dbginfo, path, li, base, verbose).cnd;
}


/// Add hotkey for IDC function (::ui_add_idckey).
/// \param hotkey   hotkey name
/// \param idcfunc  IDC function name
/// \return \ref IDCHK_

inline int add_idc_hotkey(const char *hotkey, const char *idcfunc)
{
  return callui(ui_add_idckey, hotkey, idcfunc).i;
}


/// Get the highlighted identifier in the viewer (::ui_get_highlight_2).
/// \param out_str   buffer to copy identifier to
/// \param viewer    the viewer
/// \param out_flags storage for the flags (see \ref HIF_)
/// \param flags     input flags; optionally specify a highlight slot (0-7)
/// \return false if no identifier is highlighted

inline bool get_highlight(qstring *out_str, TWidget *viewer, uint32 *out_flags, uint32 flags=0)
{
  return callui(ui_get_highlight_2, out_str, viewer, out_flags, flags).cnd;
}


/// Set the highlighted identifier in the viewer (::ui_set_highlight).
/// \param viewer   the viewer
/// \param str      the text to match, or nullptr to remove current
/// \param flags    combination of HIF_... bits (see \ref HIF_)
/// \return false if an error occurred

inline bool set_highlight(TWidget *viewer, const char *str, int flags)
{
  return callui(ui_set_highlight, viewer, str, flags).cnd;
}


#ifndef SWIG
/// Pointer to range marker function (for idaviews and hexviews)
/// This pointer is initialized by setup_range_marker()

extern void (idaapi*range_marker)(ea_t ea, asize_t size);


/// Initialize pointer to idaview marker

inline void setup_range_marker(void)
{
  void *ptr = callui(ui_get_range_marker).vptr;
  if ( ptr != nullptr )
    range_marker = reinterpret_cast<void (idaapi*)(ea_t, asize_t)>(ptr);
}

/// Inform the UI about any modifications of [ea, ea+size)

inline void mark_range_for_refresh(ea_t ea, asize_t size)
{
  if ( range_marker != nullptr )
    range_marker(ea, size);
}


/// Tell UI to refresh all idaviews and hexviews

inline void mark_all_eaviews_for_refresh(void)
{
  if ( range_marker != nullptr )
    range_marker(0, BADADDR);
}

/// Ignores range_marker during the lifetime of the object.
/// Refreshes all idaviews and hexviews at the end.
struct range_marker_suspender_t
{
  void (idaapi *backup)(ea_t ea, asize_t size);
  range_marker_suspender_t(void)
  {
    backup = range_marker;
    range_marker = nullptr;
  }
  ~range_marker_suspender_t(void)
  {
    range_marker = backup;
    mark_all_eaviews_for_refresh();
  }
};
#endif // SWIG


/// \defgroup ui_open_builtin_funcs Functions: open built-in windows
/// Convenience functions for ::ui_open_builtin
//@{

/// Open the exports window (::ui_open_builtin).
/// \param ea  index of entry to select by default
/// \return pointer to resulting window

inline TWidget *open_exports_window(ea_t ea)
{
  return (TWidget *) callui(ui_open_builtin, BWN_EXPORTS, ea).vptr;
}


/// Open the exports window (::ui_open_builtin).
/// \param ea  index of entry to select by default
/// \return pointer to resulting window

inline TWidget *open_imports_window(ea_t ea)
{
  return (TWidget *) callui(ui_open_builtin, BWN_IMPORTS, ea).vptr;
}


/// Open the names window (::ui_open_builtin).
/// \param ea  index of entry to select by default
/// \return pointer to resulting window

inline TWidget *open_names_window(ea_t ea)
{
  return (TWidget *) callui(ui_open_builtin, BWN_NAMES, ea).vptr;
}


/// Open the 'Functions' window (::ui_open_builtin).
/// \param ea  index of entry to select by default
/// \return pointer to resulting window

inline TWidget *open_funcs_window(ea_t ea)
{
  return (TWidget *) callui(ui_open_builtin, BWN_FUNCS, ea).vptr;
}


/// Open the 'Strings' window (::ui_open_builtin).
/// \param ea                index of entry to select by default
/// \param selstart,selend   only display strings that occur within this range
/// \return pointer to resulting window

inline TWidget *open_strings_window(ea_t ea, ea_t selstart=BADADDR, ea_t selend=BADADDR)
{
  return (TWidget *) callui(ui_open_builtin, BWN_STRINGS, ea, selstart, selend).vptr;
}


/// Open the segments window (::ui_open_builtin).
/// \param ea  index of entry to select by default
/// \return pointer to resulting window

inline TWidget *open_segments_window(ea_t ea)
{
  return (TWidget *) callui(ui_open_builtin, BWN_SEGS, ea).vptr;
}


/// Open the segment registers window (::ui_open_builtin).
/// \param ea  index of entry to select by default
/// \return pointer to resulting window

inline TWidget *open_segregs_window(ea_t ea)
{
  return (TWidget *) callui(ui_open_builtin, BWN_SEGREGS, ea).vptr;
}


/// Open the selectors window (::ui_open_builtin).
/// \return pointer to resulting window

inline TWidget *open_selectors_window(void)
{
  return (TWidget *) callui(ui_open_builtin, BWN_SELS, 0).vptr;
}


/// Open the signatures window (::ui_open_builtin).
/// \return pointer to resulting window

inline TWidget *open_signatures_window(void)
{
  return (TWidget *) callui(ui_open_builtin, BWN_SIGNS, 0).vptr;
}


/// Open the type libraries window (::ui_open_builtin).
/// \return pointer to resulting window

inline TWidget *open_tils_window(void)
{
  return (TWidget *) callui(ui_open_builtin, BWN_TILS, 0).vptr;
}


/// Open the local types window (::ui_open_builtin).
/// \param ordinal  ordinal of type to select by default
/// \return pointer to resulting window

inline TWidget *open_loctypes_window(int ordinal)
{
  return (TWidget *) callui(ui_open_builtin, BWN_LOCTYPS, ordinal).vptr;
}


/// Open the function calls window (::ui_open_builtin).
/// \return pointer to resulting window

inline TWidget *open_calls_window(ea_t ea)
{
  return (TWidget *) callui(ui_open_builtin, BWN_CALLS, ea).vptr;
}

/// Open the problems window (::ui_open_builtin).
/// \param ea  index of entry to select by default
/// \return pointer to resulting window

inline TWidget *open_problems_window(ea_t ea)
{
  return (TWidget *) callui(ui_open_builtin, BWN_PROBS, ea).vptr;
}


/// Open the breakpoints window (::ui_open_builtin).
/// \param ea  index of entry to select by default
/// \return pointer to resulting window

inline TWidget *open_bpts_window(ea_t ea)
{
  return (TWidget *) callui(ui_open_builtin, BWN_BPTS, ea).vptr;
}


/// Open the threads window (::ui_open_builtin).
/// \return pointer to resulting window

inline TWidget *open_threads_window(void)
{
  return (TWidget *) callui(ui_open_builtin, BWN_THREADS, 0).vptr;
}


/// Open the modules window (::ui_open_builtin).
/// \return pointer to resulting window

inline TWidget *open_modules_window(void)
{
  return (TWidget *) callui(ui_open_builtin, BWN_MODULES, 0).vptr;
}


/// Open the tracing window (::ui_open_builtin).
/// \return pointer to resulting window

inline TWidget *open_trace_window(void)
{
  return (TWidget *) callui(ui_open_builtin, BWN_TRACE, 0).vptr;
}


/// Open the call stack window (::ui_open_builtin).
/// \return pointer to resulting window

inline TWidget *open_stack_window(void)
{
  return (TWidget *) callui(ui_open_builtin, BWN_STACK, 0).vptr;
}


/// Open the cross references window (::ui_open_builtin).
/// \param ea  index of entry to select by default
/// \return pointer to resulting window

inline TWidget *open_xrefs_window(ea_t ea)
{
  return (TWidget *) callui(ui_open_builtin, BWN_XREFS, ea).vptr;
}


/// Open the frame window for the given function (::ui_open_builtin).
/// \param pfn     function to analyze
/// \param offset  offset where the cursor is placed
/// \return pointer to resulting window if 'pfn' is a valid function and the window was displayed,  \n
///                 nullptr otherwise

inline TWidget *open_frame_window(func_t *pfn, uval_t offset)
{
  return (TWidget *) callui(ui_open_builtin, BWN_FRAME, pfn, offset).vptr;
}


/// Open the navigation band window (::ui_open_builtin).
/// \param ea    sets the address of the navband arrow
/// \param zoom  sets the navband zoom level
/// \return pointer to resulting window

inline TWidget *open_navband_window(ea_t ea, int zoom)
{
  return (TWidget *) callui(ui_open_builtin, BWN_NAVBAND, ea, zoom).vptr;
}


/// Open the enums window (::ui_open_builtin).
/// \param const_id  index of entry to select by default
/// \return pointer to resulting window

inline TWidget *open_enums_window(tid_t const_id=BADADDR)
{
  return (TWidget *) callui(ui_open_builtin, BWN_ENUMS, const_id).vptr;
}


/// Open the structs window (::ui_open_builtin).
/// \param id      index of entry to select by default
/// \param offset  offset where the cursor is placed
/// \return pointer to resulting window

inline TWidget *open_structs_window(tid_t id=BADADDR, uval_t offset=0)
{
  return (TWidget *) callui(ui_open_builtin, BWN_STRUCTS, id, offset).vptr;
}


/// Open a disassembly view (::ui_open_builtin).
/// \param window_title  title of view to open
/// \param ranges        if != nullptr, then display a flow chart with the specified ranges
/// \return pointer to resulting window

inline TWidget *open_disasm_window(const char *window_title, const rangevec_t *ranges=nullptr)
{
  return (TWidget *) callui(ui_open_builtin, BWN_DISASMS, window_title, BADADDR, ranges, 0).vptr;
}


/// Open a hexdump view (::ui_open_builtin).
/// \param window_title  title of view to open
/// \return pointer to resulting window

inline TWidget *open_hexdump_window(const char *window_title)
{
  return (TWidget *) callui(ui_open_builtin, BWN_DUMPS, window_title, BADADDR, 0).vptr;
}


/// Open the notepad window (::ui_open_builtin).
/// \return pointer to resulting window

inline TWidget *open_notepad_window(void)
{
  return (TWidget *) callui(ui_open_builtin, BWN_NOTEPAD, 0).vptr;
}


/// Open the bookmarks window (::ui_open_builtin).
/// \param w The widget for which the bookmarks will open. For example,
///          this can be an IDAView, or Enums view, etc.
/// \return pointer to resulting window

inline TWidget *open_bookmarks_window(TWidget *w)
{
  return (TWidget *) callui(ui_open_builtin, BWN_BOOKMARKS, w, 0).vptr;
}


//@}

/// [Un]synchronize sources
/// \param what
/// \param with
/// \param sync
/// \return success
inline bool sync_sources(
        const sync_source_t &what,
        const sync_source_t &with,
        bool sync)
{
  return callui(ui_sync_sources, &what, &with, sync).cnd;
}


/// \defgroup ui_choose_funcs Functions: built-in choosers
/// Convenience functions for ::ui_choose and ::choose_type_t
//@{


/// Choose a signature (::ui_choose, ::chtype_idasgn).
/// \return name of selected signature, nullptr if none selected

inline char *choose_idasgn(void)
{
  return callui(ui_choose, chtype_idasgn).cptr;
}


/// Choose a type library (::ui_choose, ::chtype_idatil).
/// \param buf      output buffer to store the library name
/// \retval true   'buf' was filled with the name of the selected til
/// \retval false  otherwise

inline bool choose_til(qstring *buf)
{
  return callui(ui_choose, chtype_idatil, buf).cnd;
}


/// Choose an entry point (::ui_choose, ::chtype_entry).
/// \param title  chooser title
/// \return ea of selected entry point, #BADADDR if none selected

inline ea_t choose_entry(const char *title)
{
  ea_t ea;
  callui(ui_choose, chtype_entry, &ea, title);
  return ea;
}


/// Choose a name (::ui_choose, ::chtype_name).
/// \param title  chooser title
/// \return ea of selected name, #BADADDR if none selected

inline ea_t choose_name(const char *title)
{
  ea_t ea;
  callui(ui_choose, chtype_name, &ea, title);
  return ea;
}


/// Choose an xref to a stack variable (::ui_choose, ::chtype_name).
/// \param pfn   function
/// \param mptr  variable
/// \return ea of the selected xref, BADADDR if none selected

inline ea_t choose_stkvar_xref(func_t *pfn, member_t *mptr)
{
  ea_t ea;
  callui(ui_choose, chtype_stkvar_xref, &ea, pfn, mptr);
  return ea;
}


/// Choose an xref to an address (::ui_choose, ::chtype_xref).
/// \param to  referenced address
/// \return ea of selected xref, BADADDR if none selected

inline ea_t choose_xref(ea_t to)
{
  ea_t ea;
  callui(ui_choose, chtype_xref, &ea, to);
  return ea;
}


/// Choose an enum (::ui_choose, ::chtype_enum).
/// \param title       chooser title
/// \param default_id  id of enum to select by default
/// \return enum id of selected enum, #BADNODE if none selected

inline enum_t choose_enum(const char *title, enum_t default_id)
{
  enum_t enum_id = default_id;
  callui(ui_choose, chtype_enum, &enum_id, title);
  return enum_id;
}


/// Choose an enum, restricted by value & size (::ui_choose, ::chtype_enum_by_value_and_size).
/// If the given value cannot be found initially, this function will
/// ask if the user would like to import a standard enum.
/// \param title        chooser title
/// \param default_id   id of enum to select by default
/// \param value        value to search for
/// \param nbytes       size of value
/// \param[out] serial  serial number of imported enum member, if one was found
/// \return enum id of selected (or imported) enum, #BADNODE if none was found

inline enum_t choose_enum_by_value(
        const char *title,
        enum_t default_id,
        uint64 value,
        int nbytes,
        uchar *serial)
{
  enum_t enum_id = default_id;
  callui(ui_choose, chtype_enum_by_value_and_size, &enum_id, title, value, nbytes, serial);
  return enum_id;
}


/// Choose a function (::ui_choose, ::chtype_func).
/// \param title       chooser title
/// \param default_ea  ea of function to select by default
/// \return pointer to function that was selected, nullptr if none selected

inline func_t *choose_func(const char *title, ea_t default_ea)
{
  return callui(ui_choose, chtype_func, title, default_ea).fptr;
}


/// Choose a segment (::ui_choose, ::chtype_segm).
/// \param title       chooser title
/// \param default_ea  ea of segment to select by default
/// \return pointer to segment that was selected, nullptr if none selected

inline segment_t *choose_segm(const char *title, ea_t default_ea)
{
  return callui(ui_choose, chtype_segm, title, default_ea).segptr;
}


/// Choose a structure (::ui_choose, ::chtype_segm).
/// \param title  chooser title;
/// \return pointer to structure that was selected, nullptr if none selected

inline struc_t *choose_struc(const char *title)
{
  return callui(ui_choose, chtype_struc, title).strptr;
}


/// Choose a segment register change point (::ui_choose, ::chtype_srcp).
/// \param title  chooser title
/// \return pointer to segment register range of selected change point, nullptr if none selected

inline sreg_range_t *choose_srcp(const char *title)
{
  return callui(ui_choose, chtype_srcp, title).sraptr;
}

//@}

#ifndef SWIG

/// Get path to a structure offset (for nested structures/enums) (::ui_choose, ::chtype_strpath).

inline int choose_struc_path(
        const char *title,
        tid_t strid,
        uval_t offset,
        adiff_t delta,
        bool appzero,
        tid_t *path)
{
  return callui(ui_choose, chtype_strpath, title, strid,
                                            offset, delta, appzero, path).i;
}




/// Invoke the chooser with a chooser object (::ui_choose, ::chtype_generic).
/// see the choose() function above

//lint -sem(choose,custodial(1))
inline ssize_t choose(chooser_base_t *ch, const void *def_item)
{
  return callui(ui_choose, chtype_generic, ch, def_item).ssize;
}

#endif // SWIG


/// Get the underlying object of the specified chooser (::ui_get_chooser_obj).
///
/// This attemps to find the choser by its title and, if found, returns
/// the result of calling its chooser_base_t::get_chooser_obj() method.
///
/// \note This is object is chooser-specific.
/// \return the object that was used to create the chooser

inline void *get_chooser_obj(const char *chooser_caption)
{
  return callui(ui_get_chooser_obj, chooser_caption).vptr;
}

/// Get the text corresponding to the index N in the chooser data.
/// Use -1 to get the header.

inline bool get_chooser_data(
        qstrvec_t *out,
        const char *chooser_caption,
        int n)
{
  return callui(ui_get_chooser_data, out, chooser_caption, n).cnd;
}


/// Enable item-specific attributes for chooser items (::ui_enable_chooser_item_attrs).
/// For example: color list items differently depending on a criterium.             \n
/// If enabled, the chooser will generate ui_get_chooser_item_attrs                 \n
/// events that can be intercepted by a plugin to modify the item attributes.       \n
/// This event is generated only in the GUI version of IDA.                         \n
/// Specifying #CH_ATTRS bit at the chooser creation time has the same effect.
/// \return success

inline bool idaapi enable_chooser_item_attrs(const char *chooser_caption, bool enable)
{
  return callui(ui_enable_chooser_item_attrs, chooser_caption, enable).cnd;
}


/// See show_wait_box()

THREAD_SAFE AS_PRINTF(1, 0) inline void show_wait_box_v(const char *format, va_list va)
{
  callui(ui_mbox, mbox_wait, format, va);
}


/// Display a dialog box with "Please wait...".
/// The behavior of the dialog box can be configured with well-known     \n
/// tokens, that should be placed at the start of the format string:     \n
///   "NODELAY\n": the dialog will show immediately, instead of          \n
///                appearing after usual grace threshold                 \n
///   "HIDECANCEL\n": the cancel button won't be added to the dialog box \n
///                   and user_cancelled() will always return false (but \n
///                   can be called to refresh UI)                       \n
///                   Using "HIDECANCEL" implies "NODELAY"               \n
/// Plugins must call hide_wait_box() to close the dialog box, otherwise \n
/// the user interface will remain disabled.                             \n
///
/// Note that, if the wait dialog is already visible, show_wait_box() will  \n
///   1) push the currently-displayed text on a stack                       \n
///   2) display the new text                                               \n
/// Then, when hide_wait_box() is called, if that stack isn't empty its top \n
/// label will be popped and restored in the wait dialog.                   \n
/// This implies that a plugin should call hide_wait_box() exactly as many  \n
/// times as it called show_wait_box(), or the wait dialog might remain     \n
/// visible and block the UI.                                               \n
/// Also, in case the plugin knows the wait dialog is currently displayed,  \n
/// alternatively it can call replace_wait_box(), to replace the text of the\n
/// dialog without pushing the currently-displayed text on the stack.
THREAD_SAFE AS_PRINTF(1, 2) inline void show_wait_box(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  show_wait_box_v(format, va);
  va_end(va);
}


/// Hide the "Please wait dialog box"

THREAD_SAFE inline void hide_wait_box(void)
{
  // stupid watcom requires va_list should not be nullptr
  callui(ui_mbox, mbox_hide, nullptr, &callui);
}


/// Replace the label of "Please wait dialog box"

THREAD_SAFE AS_PRINTF(1, 2) inline void replace_wait_box(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  callui(ui_mbox, mbox_replace, format, va);
  va_end(va);
}


/// Issue a beeping sound (::ui_beep).
/// \param beep_type  ::beep_t

inline void beep(beep_t beep_type=beep_default)
{
  callui(ui_beep, beep_type);
}


/// Display copyright warning (::ui_copywarn).
/// \return yes/no

inline bool display_copyright_warning(void)
{
  return callui(ui_copywarn).cnd;
}

#endif  // __UI__ END OF UI SERVICE FUNCTIONS


/// Show a message box asking to send the input file to support@hex-rays.com.
/// \param format  the reason why the input file is bad

THREAD_SAFE AS_PRINTF(1, 2) inline void ask_for_feedback(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  callui(ui_mbox, mbox_feedback, format, va);
  va_end(va);
}

/// Output a formatted string to the output window (msg)
/// preprended with "**DATABASE IS CORRUPTED: "

/// Display a dialog box and wait for the user to input an address (::ui_ask_addr).
/// \param addr     in/out parameter. contains pointer to the address.
/// \param format   printf() style format string with the question
/// \retval 0  the user pressed Esc.
/// \retval 1  ok, the user entered an address

AS_PRINTF(2, 3) inline bool ask_addr(ea_t *addr, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  bool ok = callui(ui_ask_addr, addr, format, va).cnd;
  va_end(va);
  return ok;
}


/// Display a dialog box and wait for the user to input an segment name (::ui_ask_seg).
/// This function allows to enter segment register names, segment base
/// paragraphs, segment names to denote a segment.
/// \param sel      in/out parameter. contains selector of the segment
/// \param format   printf() style format string with the question
/// \retval  0  if the user pressed Esc.  \n
/// \retval  1  ok, the user entered an segment name

AS_PRINTF(2, 3) inline bool ask_seg(sel_t *sel, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  bool ok = callui(ui_ask_seg, sel, format, va).cnd;
  va_end(va);
  return ok;
}


/// Display a dialog box and wait for the user to input an number (::ui_ask_long).
/// The number is represented in C-style.
/// This function allows to enter any IDC expression and
/// properly calculates it.
/// \param value    in/out parameter. contains pointer to the number
/// \param format   printf() style format string with the question
/// \retval 0 if the user pressed Esc.  \n
/// \retval 1 ok, the user entered a valid number.

AS_PRINTF(2, 3) inline bool ask_long(sval_t *value, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  bool ok = callui(ui_ask_long, value, format, va).cnd;
  va_end(va);
  return ok;
}


//---------------------------------------------------------------------------
//      E R R O R / W A R N I N G / I N F O   D I A L O G   B O X E S
//---------------------------------------------------------------------------

/// If this variable is set, then dialog boxes will not appear on the screen.
/// Warning/info messages are shown in the messages window.           \n
/// The default value of user input dialogs will be returned to the
/// caller immediately.                                               \n
/// This variable is used to enable unattended work of ida.

idaman bool ida_export_data batch;


/// Exiting because of a a fatal error?
/// Is non-zero if we are exiting with from the error() function.

idaman int ida_export_data errorexit;


/// Display error dialog box and exit.
/// If you just want to display an error message and let IDA continue,
/// do NOT use this function! Use warning() or info() instead.
/// \param format  printf() style message string.
///                It may have some prefixes, see 'Format of dialog box' for details.

THREAD_SAFE AS_PRINTF(1, 2) NORETURN inline void error(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  verror(format, va);
  // NOTREACHED
}


/// Display warning dialog box and wait for the user to press Enter or Esc.
/// This messagebox will by default contain a "Don't display this message again"  \n
/// checkbox if the message is repetitively displayed. If checked, the message    \n
/// won't be displayed anymore during the current IDA session.                    \n
/// \param format  printf() style format string.
///                It may have some prefixes, see 'Format of dialog box' for details.
/// \param va       pointer to variadic arguments.

THREAD_SAFE AS_PRINTF(1, 0) inline void vwarning(const char *format, va_list va)
{
  callui(ui_mbox, mbox_warning, format, va);
}

THREAD_SAFE AS_PRINTF(1, 2) inline void warning(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vwarning(format, va);
  va_end(va);
}


/// Display info dialog box and wait for the user to press Enter or Esc.
/// This messagebox will by default contain a "Don't display this message again"    \n
/// checkbox. If checked, the message will never be displayed anymore (state saved  \n
/// in the Windows registry or the idareg.cfg file for a non-Windows version).
/// \param format  printf() style format string.
///                It may have some prefixes, see 'Format of dialog box' for details.
/// \param va       pointer to variadic arguments.

THREAD_SAFE AS_PRINTF(1, 0) inline void vinfo(const char *format, va_list va)
{
  callui(ui_mbox, mbox_info, format, va);
}

THREAD_SAFE AS_PRINTF(1, 2) inline void info(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vinfo(format, va);
  va_end(va);
}


/// Display "no memory for module ..." dialog box and exit.
/// \param format   printf() style message string.
/// \param va       pointer to variadic arguments.

THREAD_SAFE AS_PRINTF(1, 0) NORETURN inline void vnomem(const char *format, va_list va)
{
  callui(ui_mbox, mbox_nomem, format, va);
  // NOTREACHED
  abort(); // to suppress compiler warning or error
}

THREAD_SAFE AS_PRINTF(1, 2) NORETURN inline void nomem(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  vnomem(format, va);
  // NOTREACHED
}


/// Output a formatted string to the output window [analog of printf()].
/// Everything appearing on the output window may be written
/// to a text file. For this the user should define the following environment
/// variable:                       \n
///         set IDALOG=idalog.txt
///
/// \param format  printf() style message string.
/// \param va       pointer to variadic arguments.
/// \return number of bytes output

THREAD_SAFE AS_PRINTF(1, 0) inline int vmsg(const char *format, va_list va)
{
  return callui(ui_msg, format, va).i;
}

THREAD_SAFE AS_PRINTF(1, 2) inline int msg(const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int nbytes = vmsg(format, va);
  va_end(va);
  return nbytes;
}

#ifndef SWIG

/*! \defgroup FORM_C ask_form()/open_form()

  \brief This module describes how to generate a custom form.

  <pre>

  The following keywords might appear at the beginning of the 'form' argument
  (case insensitive):

  STARTITEM number

    where number is a number of input field the cursor will stand on.
    By default the cursor is in the first field of the dialog box.
    The input fields are numbered from 0 (the first field is field 0).

  BUTTON name caption

    Alternative caption for a button. It may contain the character
    to highlight in this form:  ~Y~es
    Valid button names are: YES, NO, CANCEL
    For example:
        BUTTON YES Please do
        BUTTON NO Nope
        BUTTON CANCEL NONE

    By default the NO button is not displayed. If it is displayed, then
    the return value of the function will be different!
    (see the function description)

    Empty text means that there won't be any corresponding button.
    (you may also use NONE as the caption to hide it)

    A * after the button name means that this button will be the default:

      BUTTON CANCEL* Cancel

  Next, if the dialog box is kept in IDA.HLP, the following may appear:
  (this defines help context for the whole dialog box)

  @hlpMessageName[]

  If the form is not in IDA.HLP file, then it can have a built-in
  help message. In this case the help screen should be enclosed in the
  following keywords:

  HELP
  ....
  ....
  ....
  ENDHELP

  Each keyword should be on a separate line.

  Next there must be the title line and two empty lines.
  Most of the text in the dialog box text string is copied to the dialog
  without modification. There are three special cases:

        - dynamic labels (format parameters)
        - callback arguments
        - input fields

  For example, this dialog box:

  ------ format:
        Sample dialog box


        This is sample dialog box for %A
        using address %$

        <~E~nter value:N::18::>

  ------

  Contains two dynamic labels (text %A and address %$) and one input field
  (numerical input box with the label "Enter value").

  Parameters for the dynamic labels and input fields are taken from the
  function's input arguments (va_list). The corresponding argument should
  contain a pointer (sic, pointer) to the value to be displayed.

  The dialog box above should be called as

                \code
                char *string = "something";
                ea_t addr = someaddr;
                uval_t answer = 0;
                int ok = ask_form(format, string, &addr, &answer);
                \endcode


  Dynamic labels are used to specify variant parts of the dialog box text.
  They use the following syntax:

        %nT

  where
        n  - optional decimal field ID, which may be used in the
             ::form_actions_t calls to get/set label value at runtime
        T  - a character specifying type of input field. All input field
             types (except B and K) are valid format specifiers. See below
             for the list.


  There are two special specifiers for callbacks:

  The combination '%/' corresponds to a callback function that will be
  called when any of the fields is modified. The callback type is ::formchgcb_t.
  There can be only one such callback. It corresponds to the first variadic
  argument regardless of its exact position in the format string.

  The combination '%*' is used to store user data (void *) in the form.
  This data can be later retrieved from the ::formchgcb_t callback via the
  form action method get_ud().

  Input fields use the following syntax:

  <label:type:width:swidth:@hlp[]>

  where
        label - any text string serving as label for the input field
                the label may contain an accelerator key like this: "~O~pen"
                (O is the accelerator key; Alt-O will work too)
        type  - a character specifying type of input field.
                The form() function will perform initial validation of
                value specified by the user and convert it appropriately.
                See table of input field types below. The type can be followed
                by a decimal number, an input field ID.
        width - decimal number specifying the maximum possible number of
                characters that can be entered into the input field
                for X: decimal number specifying size of the buffer
                  of characters that can be entered into the input field
                  passed for text input fields (including terminating 0).
                  if omitted or <0, assumed to be at least MAXSTR
                for B, k: the code generated when the user presses the
                  button (passed to the button callback)
                for f (path to file) this attribute specifies the dialog type:
                  0-'open file' dialog box
                  1-'save file' dialog box
                for F (folder) it is ignored
                for f, F: buffer is assumed to be at least QMAXPATH long
                for b (combobox) this attribute specifies the readonly attribute:
                  0   - read-only combobox
                  > 0 - editable combobox
                for n, N, D, O, Y, H, M: the width can have a '+' prefix.
                  in this case, if the entered value starts with '+' or '-'
                  sign, it will be added to or subtracted from the initial
                  value. the caller will receive the result of this operation
        swidth -decimal number specifying width of visible part of input field
                this number may be omitted.
                for E, t: decimal number specifying the width of the input area.
                  for these types the number cannot be omitted.
                  note that the height is calculated automatically
        @hlp[]- help context for the input field. you may replace the
                help context with '::' (two colons) if you don't want to
                specify help context. The help context is a number of help
                page from IDA.HLP file.


  Input field types                               va_list parameter
  -----------------                               -----------------

  q - UTF-8 string                                ::qstring*
  h - HTML text                                   char * (only for GUI version; only for dynamic labels; no input)
  S - segment                                     ::sel_t*
  N - hex number, C notation                      ::uval_t*
  n - signed hex number, C notation               ::sval_t*
  L - C notation number                           ::uint64*
      (prefix 0x - hex, 0 - octal, otherwise decimal)
  l - same as L but with optional sign            ::int64*
  M - hex number, no "0x" prefix                  ::uval_t*
  D - decimal number                              ::sval_t*
  O - octal number, C notation                    ::sval_t*
  Y - binary number, "0b" prefix                  ::sval_t*
  H - char value, C notation                      ::sval_t*
  $ - address                                     ::ea_t*
  i - ident                                       ::qstring*
  B - button                                      ::buttoncb_t*
  k - txt: button (same as B)/gui: hyperlink      ::buttoncb_t*
  K - color button                                ::bgcolor_t*
  F - path to folder                              char* at least #QMAXPATH size
  f - path to file                                char* at least #QMAXPATH size
  y - type declaration                            ::qstring*
  X - command                                     char* at least #MAXSTR size
  E - chooser                                     ::chooser_base_t * - embedded chooser
                                                  ::sizevec_t * - in/out: selected lines (0-based)
                                                    selected rows are saved to this array
                                                    for modal forms only
                                                    (NB: this field takes two args)
  t - multi line text control                     ::textctrl_info_t *
  b - combobox (dropdown list)                    ::qstrvec_t * - the list of items
                                                  int* or ::qstring* - the preselected item
                                                    (::qstring* when the combo is editable, i.e. width field is >0)
  p - UTF-8 string                                ::qstring* - echoed as a password field (i.e., with '*' masks)

  The M, n, N, D, O, Y, H, $ fields try to parse the input as an IDC expression
  and convert the result into the required value type

  If the buffer for 'F' field contains filemasks and descriptions like this:
    *.exe|Executable files,*.dll|Dll files
  they will be used in the dialog box filter.

  The hint message can be specified before the label enclosed in '#':

  <#hint message#label:...>

  Radiobuttons and checkboxes are represented by:

  <label:type>
  <label:type>>         - end of block

  where valid types are C and R
  (you may use lowercase 'c' and 'r' if you need to create two radiobutton
  or checkbox groups on the same lines). The field ID of the whole group
  can be specified between the brackets: <label:type>ID>

  field types           va_list parameter
  -----------           -----------------

  C - checkbox          ushort*                 bit mask of checkboxes
  R - radiobutton       ushort*                 number of radiobutton

  The group box title and hint messages can be specified like this:

  <#item hint[#group box title[#group box hint]]#label:type>

  The group box title and the group box hint can be specified only in the
  first item of the box. If the item hint doesn't exist, it should be
  specified as an empty hint (##title##).
  The subsequent items can have an item hint only:

  <#item hint#label:type>

  Initial values of input fields are specified in the corresponding
  input/output parameters (taken from va_list array).

  OK, Cancel and (possibly) Help buttons are displayed at the bottom of
  the dialog box automatically. Their captions can be changed by the BUTTON
  keywords described at the beginning of this page.

  Input field definition examples:

   <Kernel analyzer options ~1~:B:0:::>
   <~A~nalysis enabled:C>
   <~I~ndicator enabled:C>>
   <Names pre~f~ix  :q:15:15::>
   <~O~utput file:f:1:64::>
   <~O~utput directory:F::64::>

  Resizable fields can be separated by splitters (GUI only).

  A vertical splitter is represented by <|>. E.g.,:
    <~Chooser~:E1:0:40:::><|><~E~ditor:t2:0:40:::>
  whereas a horizontal splitter is represented by <->. E.g.,:
    <~Chooser~:E1:0:40:::>
    <->
    <~E~ditor:t2:0:40:::>

  It's also possible to organize fields by tabs (GUI only),
  by adding a: <=:tab_label> after a series of fields. E.g.,:

    <This is a checkbox:c>>
    <=:Tab with a checkbox>
    <A numeric input:D::10::>
    <=:Tab with numeric input>

  </pre>
*/
//@{
//----------------------------------------------------------------------
//      F O R M S  -  C O M P L E X   D I A L O G   B O X E S
//----------------------------------------------------------------------

/// See ask_form()

inline int vask_form(const char *format, va_list va)
{
  return callui(ui_ask_form, format, va).i;
}

/// Display a dialog box and wait for the user.
/// If the form contains the "BUTTON NO <title>" keyword, then the return values
/// are the same as in the ask_yn() function (\ref ASKBTN_)
/// \param form  dialog box as a string. see \ref FORM_C
/// \retval 0    no memory to display or form syntax error
///              (a warning is displayed in this case).
///              the user pressed the 'No' button (if the form has it) or
///              the user cancelled the dialog otherwise.
///              all variables retain their original values.
/// \retval 1    ok, all input fields are filled and validated.
/// \retval -1   the form has the 'No' button and the user cancelled the dialog

inline int ask_form(const char *form, ...)
{
  va_list va;
  va_start(va, form);
  int code = vask_form(form, va);
  va_end(va);
  return code;
}


/// Create and/or activate dockable modeless form (::ui_open_form).
/// \param format  string
/// \param flags   \ref WIDGET_OPEN
/// \param va      args
/// \return pointer to resulting TWidget

inline TWidget *vopen_form(const char *format, uint32 flags, va_list va)
{
  return (TWidget *)callui(ui_open_form, format, flags, va).vptr;
}


/// Display a dockable modeless dialog box and return a handle to it.
/// The modeless form can be closed in the following ways:
/// - by pressing the small 'x' in the window title
/// - by calling form_actions_t::close() from the form callback
///   (\ref form_actions_t)
/// \note pressing the 'Yes/No/Cancel' buttons does not close the modeless
///       form, except if the form callback explicitly calls close().
/// \param form      dialog box as a string. see \ref FORM_C
/// \param flags     \ref WIDGET_OPEN
/// \return handle to the form or nullptr.
///         the handle can be used with TWidget functions: close_widget()/activate_widget()/etc

inline TWidget *open_form(const char *form, uint32 flags, ...)
{
  va_list va;
  va_start(va, flags);
  TWidget *widget = vopen_form(form, flags, va);
  va_end(va);
  return widget;
}

//@} FORM_C


/// Functions available from ::formchgcb_t.
/// For getters/setters for specific field values, see #DEF_SET_METHOD.
struct form_actions_t
{
  /// Get value of an input field.
  /// \return false if no such field id or invalid field type (B)
  virtual bool idaapi _get_field_value(int field_id, void *buf) = 0;

  /// Set value of an input field.
  /// \return false if no such field id or invalid field type (B)
  virtual bool idaapi _set_field_value(int field_id, const void *buf) = 0;

  /// Enable or disable an input field.
  /// \return false if no such field id
  virtual bool idaapi enable_field(int field_id, bool enable) = 0;

  /// Show or hide an input field.
  /// \return false if no such field id
  virtual bool idaapi show_field(int field_id, bool display) = 0;

  /// Move/Resize an input field.
  /// Parameters specified as -1 are not modified.
  /// \return false no such field id
  virtual bool idaapi move_field(int field_id, int x, int y, int w, int h) = 0;

  /// Get currently focused input field.
  /// \return -1 if no such field
  virtual int idaapi get_focused_field(void) = 0;

  /// Set currently focused input field.
  /// \return false if no such field id
  virtual bool idaapi set_focused_field(int field_id) = 0;

  /// Refresh a field
  virtual void idaapi refresh_field(int field_id) = 0;

  /// Close the form
  virtual void idaapi close(int close_normally) = 0;

  /// Retrieve the user data specified through %*
  virtual void *idaapi get_ud() = 0;

  /// Get value of an UTF-8 string input field.
  /// \return false if no such field id or invalid field type (B)
  virtual bool idaapi _get_str_field_value(int field_id, char *buf, const size_t bufsize) = 0;

/// Helper to define functions in ::form_actions_t that get/set field values of different types.
/// Please see this file's source code for specific uses.
#define DEF_SET_METHOD(NAME, TYPE)                                   \
  bool idaapi set_ ## NAME ## _value(int field_id, const TYPE *val)  \
  {                                                                  \
    return _set_field_value(field_id, val);                          \
  }
/// \copydoc DEF_SET_METHOD
#define DEF_FIELD_METHOD(NAME, TYPE)                                 \
  bool idaapi get_ ## NAME ## _value(int field_id, TYPE *val)        \
  {                                                                  \
    return _get_field_value(field_id, val);                          \
  }                                                                  \
  DEF_SET_METHOD(NAME, TYPE)
/// \copydoc DEF_SET_METHOD
#define DEF_STR_FIELD_METHOD(NAME            )                       \
  bool idaapi get_ ## NAME ## _value(int field_id, char *buf, const size_t bufsize) \
  {                                                                  \
    return _get_str_field_value(field_id, buf, bufsize);             \
  }                                                                  \
  DEF_SET_METHOD(NAME, char)

  // get/set value of radio button (r, R)
  DEF_FIELD_METHOD(radiobutton, ushort)
  // get/set value of radio button group
  DEF_FIELD_METHOD(rbgroup, ushort)
  // get/set value of check box (c, C)
  DEF_FIELD_METHOD(checkbox, ushort)
  // get/set value of check box group
  DEF_FIELD_METHOD(cbgroup, ushort)
  // get/set value of color control (K)
  DEF_FIELD_METHOD(color, bgcolor_t)
  // get/set embedded chooser selected items (E)
  DEF_FIELD_METHOD(chooser, sizevec_t)
  // get/set value of editable combo box (b when field 'width' >0)
  DEF_FIELD_METHOD(combobox, qstring)
  // get/set selected item of read-only combo box (b when field 'width' ==0)
  DEF_FIELD_METHOD(combobox, int)
  // get/set value of multiline text input control (t)
  DEF_FIELD_METHOD(text, textctrl_info_t)
  // get/set text of buttons
  DEF_FIELD_METHOD(button, qstring)
  // get/set value of dynamic label (%)
  DEF_STR_FIELD_METHOD(label)
  // get/set string value (X, F, f)
  DEF_STR_FIELD_METHOD(string) //-V524 body is equal to get_label_value
  // get/set path value (F, f)
  DEF_STR_FIELD_METHOD(path)   //-V524 body is equal to get_label_value
  // get/set string value (q, I, y, p)
  DEF_FIELD_METHOD(string, qstring)
  // get/set identifier value (I)
  DEF_FIELD_METHOD(ident, qstring)
  // get/set value of segment (S)
  DEF_FIELD_METHOD(segment, sel_t)
  // get/set signed value (n, D, O, Y, H)
  DEF_FIELD_METHOD(signed, sval_t)
  // get/set unsigned value (N, M)
  DEF_FIELD_METHOD(unsigned, uval_t)
  // get/set value of default base (usually hex) number (l)
  DEF_FIELD_METHOD(int64, int64)
  // get/set value of default base (usually hex) number (L)
  DEF_FIELD_METHOD(uint64, uint64)
  // get/set address value ($)
  DEF_FIELD_METHOD(ea, ea_t)

#undef DEF_FIELD_METHOD
#undef DEF_SET_METHOD
#undef DEF_STR_FIELD_METHOD

  enum dlgbtn_t
  {
    dbt_yes,
    dbt_cancel,
    dbt_no
  };

  // Enable or disable a standard dialog button (Yes, Cancel, None)
  virtual bool enable_dialog_button(dlgbtn_t btn, bool enabled) = 0;

  // Get state of a standard button
  virtual bool is_dialog_button_enabled(dlgbtn_t btn) = 0;

  // Update the list of available options for a combobox (b)
  //
  // Note: the contents of the `qstrvec_t` that was passed to ask_form/open_form will be modified
  virtual void swap_combobox_choices(int fid, qstrvec_t &items) = 0;

  /// Set the label text of an input field.
  /// If the text is empty, the label will be deleted.
  /// Currently supports 'multi line text control' field type.
  /// GUI version only.
  /// \return success
  virtual bool idaapi set_field_label(int fid, const qstring &text) = 0;
};


/// Callback. Called when an input field is modified.
/// The callback will be also called before displaying the form and as soon
/// as the user presses the 'Yes/No/Cancel' buttons or closes the window.
/// The callback will be called for both modal and modeless window.
/// \param field_id  id of the modified field or a special field id \ref CB_
/// \param fa helper class with useful virtual functions
/// \retval 0        continue editing
/// \retval >0       form will be closed
/// \note the return value is used by IDA only for modal forms, and only for
///       the following special field ids: CB_CLOSE, CB_YES, CB_NO, CB_CANCEL
///       (for modeless forms CB_CLOSE is also used).

typedef int idaapi formchgcb_t(int field_id, form_actions_t &fa);


/// Callback. Called when a button is clicked.
/// \param button_code button code as specified in the form
/// \param fa helper class with useful virtual functions
/// \retval 0        currently ignored

typedef int idaapi buttoncb_t(int button_code, form_actions_t &fa);


#endif // SWIG

//---------------------------------------------------------------------------
//      Y E S / N O   D I A L O G   B O X
//---------------------------------------------------------------------------

/// \defgroup ASKBTN_ Button IDs
/// used by ask_yn() and ask_buttons()
//@{
#define ASKBTN_YES     1  ///< Yes button
#define ASKBTN_NO      0  ///< No button
#define ASKBTN_CANCEL -1  ///< Cancel button
#define ASKBTN_BTN1    1  ///< First (Yes) button
#define ASKBTN_BTN2    0  ///< Second (No) button
#define ASKBTN_BTN3   -1  ///< Third (Cancel) button
//@}


THREAD_SAFE AS_PRINTF(5, 0) inline int vask_buttons(
        const char *Yes,
        const char *No,
        const char *Cancel,
        int deflt,
        const char *format,
        va_list va)
{
  return callui(ui_ask_buttons, Yes, No, Cancel, deflt, format, va).i;
}


AS_PRINTF(2, 0) inline int vask_yn(int deflt, const char *format, va_list va)
{
  return vask_buttons(nullptr, nullptr, nullptr, deflt, format, va);
}


/// Display a dialog box and get choice from "Yes", "No", "Cancel".
/// \param deflt    default choice: one of \ref ASKBTN_
/// \param format   The question in printf() style format
/// \return the selected button (one of \ref ASKBTN_). Esc key returns #ASKBTN_CANCEL.

AS_PRINTF(2, 3) inline int ask_yn(int deflt, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  int code = vask_yn(deflt, format, va);
  va_end(va);
  return code;
}


/// Display a dialog box and get choice from maximum three possibilities (::ui_ask_buttons).
/// \note for all buttons:
///   - use "" or nullptr to take the default name for the button.
///   - prepend "HIDECANCEL\n" in 'format' to hide the Cancel button
/// \param Yes     text for the first button
/// \param No      text for the second button
/// \param Cancel  text for the third button
/// \param deflt   default choice: one of \ref ASKBTN_
/// \param format  printf-style format string for question. It may have some prefixes, see below.
/// \param va      parameters for the format string
/// \return one of \ref ASKBTN_ specifying the selected button (Esc key returns Cancel/3rd button value)

AS_PRINTF(5, 6) inline int ask_buttons(
        const char *Yes,
        const char *No,
        const char *Cancel,
        int deflt,
        const char *format,
        ...)
{
  va_list va;
  va_start(va, format);
  int code = vask_buttons(Yes, No, Cancel, deflt, format, va);
  va_end(va);
  return code;
}

//------------------------------------------------------------------------
/* Format of dialog box (actually they are mutliline strings
                         delimited by newline characters)

  The very first line of dialog box can specify a dialog box
  title if the following line appears:

  TITLE title string


  Then, the next line may contain an icon to display
  in the GUI version (ignored by the text version):

  ICON NONE          (no icon)
       INFO          (information icon)
       QUESTION      (question icon)
       WARNING       (warning icon)
       ERROR         (error icon)


  Then, the next line may contain a 'Don't display this message again'
  checkbox. If this checkbox is selected and the user didn't select cancel,
  the button he selected is saved and automatically returned.

  AUTOHIDE NONE      (no checkbox)
           DATABASE  (return value is saved to database)
           REGISTRY  (return value is saved to Windows registry or idareg.cfg
                      if non-Windows version)
           SESSION   (return value is saved for the current IDA session)
  It is possible to append "*" to the AUTOHIDE keywords to have this checkbox
  initially checked. For example: "AUTOHIDE REGISTRY*"

  To hide the cancel button the following keyword can be used:

  HIDECANCEL

  To enable rich text (i.e., HTML) in the Qt version of IDA,
  the following keyword can be used:

  RICHTEXT

  Please note that the user still can cancel the dialog box by pressing Esc
  or clicking on the 'close window' button.

  Finally, if the dialog box is kept in IDA.HLP, the following may appear
  to add a Help button (this defines help context for the whole dialog box):

  @hlpMessageName[]


  Each keyword should be alone on a line.

  Next, a format string must be specified.
  To center message lines in the text version, start them with '\3' character
  (currently ignored in the GUI version).
*/

//---------------------------------------------------------------------------
//      A S K   S T R I N G   O F   T E X T
//---------------------------------------------------------------------------

/// Display a dialog box and wait for the user to input a text string (::ui_ask_str).
/// Use this function to ask one-line text. For multiline input, use ask_text().
/// This function will trim the trailing spaces.
/// \param str      qstring to fill. Can contain the default value. Cannot be nullptr.
/// \param hist     category of history lines. an arbitrary number.         \n
///                 this number determines lines accessible in the history  \n
///                 of the user input (when he presses down arrow)          \n
///                 One of \ref HIST_ should be used here
/// \param format   printf() style format string with the question
/// \param va       pointer to variadic arguments.
/// \return false if the user cancelled the dialog, otherwise returns true.

AS_PRINTF(3, 0) inline bool vask_str(
        qstring *str,
        int hist,
        const char *format,
        va_list va)
{
  return callui(ui_ask_str, str, hist, format, va).cnd;
}

AS_PRINTF(3, 4) inline bool ask_str(qstring *str, int hist, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  bool result = vask_str(str, hist, format, va);
  va_end(va);
  return result;
}

/// \defgroup HIST_ Input line history constants
/// passed as 'hist' parameter to ask_str()
//@{
#define HIST_SEG    1           ///< segment names
#define HIST_CMT    2           ///< comments
#define HIST_SRCH   3           ///< search substrings
#define HIST_IDENT  4           ///< names
#define HIST_FILE   5           ///< file names
#define HIST_TYPE   6           ///< type declarations
#define HIST_CMD    7           ///< commands
#define HIST_DIR    8           ///< directory names (text version only)
//@}


/// Display a dialog box and wait for the user to input an identifier.
/// If the user enters a non-valid identifier, this function displays a warning
/// and allows the user to correct it.
/// \param str      qstring to fill. Can contain the default value. Cannot be nullptr.
/// \param format   printf() style format string with the question
/// \return false if the user cancelled the dialog, otherwise returns true.

AS_PRINTF(2, 3) inline bool ask_ident(qstring *str, const char *format, ...)
{
  va_list va;
  va_start(va, format);
  bool result = vask_str(str, HIST_IDENT, format, va);
  va_end(va);
  return result;
}


/// Display a dialog box and wait for the user to input multiline text (::ui_ask_text).
/// \param answer   output buffer
/// \param max_size maximum size of text in bytes including terminating zero (0 for unlimited)
/// \param defval   default value. will be displayed initially in the input line.
///                   may be nullptr.
/// \param format   printf() style format string with the question.
///                 the following options are accepted at its beginning:
///                    "ACCEPT TABS\n": accept tabulations in the input
///                    "NORMAL FONT\n": use regular font (otherwise the notepad font)
/// \param va       pointer to variadic arguments.
/// \return false-if the user pressed Esc, otherwise returns true.

AS_PRINTF(4, 0) inline bool vask_text(
        qstring *answer,
        size_t max_size,
        const char *defval,
        const char *format,
        va_list va)
{
  return callui(ui_ask_text, answer, max_size, defval, format, va).cnd;
}

AS_PRINTF(4, 5) inline bool ask_text(
        qstring *answer,
        size_t max_size,
        const char *defval,
        const char *format,
        ...)
{
  va_list va;
  va_start(va, format);
  bool result = vask_text(answer, max_size, defval, format, va);
  va_end(va);
  return result;
}


//---------------------------------------------------------------------------
//      A S K   A D D R E S S E S ,   N A M E S ,   N U M B E R S ,   E T C .
//---------------------------------------------------------------------------

/// Display a dialog box and wait for the user to input a file name (::ui_ask_file).
/// This function displays a window with file names present in the directory
/// pointed to by 'defval'.
///
/// The 'format' parameter can contain a 'FILTER' description, of the
/// form 'description1|{wildcard1}+|...|descriptionN|{wildcardsN}+',
/// where each file type description has a corresponding set of one
/// (or more) ';'-separated mask(s). E.g.,
/// \code
///    Text files|*.txt|Executable files|*.exe;*.bin
/// \endcode
///
/// \param for_saving will the filename be used to save a file?
/// \param defval    default value. will be displayed initially in the input line.
///                  may be nullptr may be or a wildcard file name.
/// \param format    printf-style format string with the dialog title, possibly including a filter.
/// \param va        pointer to variadic arguments.
/// \return nullptr     the user cancelled the dialog.
/// Otherwise the user entered a valid file name.

AS_PRINTF(3, 0) inline char *vask_file(
        bool for_saving,
        const char *defval,
        const char *format,
        va_list va)
{
  return callui(ui_ask_file, for_saving, defval, format, va).cptr;
}


AS_PRINTF(3, 4) inline char *ask_file(
        bool for_saving,
        const char *defval,
        const char *format,
        ...)
{
  va_list va;
  va_start(va, format);
  char *answer = vask_file(for_saving, defval, format, va);
  va_end(va);
  return answer;
}


//---------------------------------------------------------------------------
//      A D D - O N S
//---------------------------------------------------------------------------

/// Information about an installed add-on (e.g. a plugin)
struct addon_info_t
{
  size_t cb;                //< size of this structure
  const char *id;           //< product code, e.g. "com.hexrays.hexx86w". Must be unique
  const char *name;         //< descriptive name, e.g. "Hex-Rays x86 Decompiler (Windows)"
  const char *producer;     //< e.g. "Hex-Rays SA"
  const char *version;      //< version string, e.g. 1.5.110408
  const char *url;          //< URL of the product http://www.hex-rays.com/decompiler.shtml
  const char *freeform;     //< any string, e.g. "Copyright (c) 2007-2023 Hex-Rays"
  const void *custom_data;  //< custom data (license ID etc). Can be nullptr. Not displayed in UI.
  size_t custom_size;

  /// Constructor
  addon_info_t()
    : cb(sizeof(addon_info_t)),
      id(nullptr),
      name(nullptr),
      producer(nullptr),
      version(nullptr),
      url(nullptr),
      freeform(nullptr),
      custom_data(nullptr),
      custom_size(0)
  {}
};

#ifndef __UI__

/// \defgroup ui_addons_funcs Functions: add-ons
/// Convenience functions for ::ui_addons
//@{

/// Register an add-on. Show its info in the About box.
/// For plugins, should be called from init() function
/// (repeated calls with the same product code overwrite previous entries)
/// returns: index of the add-on in the list, or -1 on error

inline int register_addon(const addon_info_t *info)
{
  return callui(ui_addons, 0, info).i;
}


/// Get number of installed addons

inline int addon_count()
{
  return callui(ui_addons, 1).i;
}


/// Get info about a registered addon with a given product code.
/// info->cb must be valid!
/// NB: all pointers are invalidated by next call to register_addon or get_addon_info
/// \return false if not found

inline bool get_addon_info(const char *id, addon_info_t *info)
{
  return callui(ui_addons, 2, id, info).cnd;
}


/// Get info about a registered addon with specific index.
/// info->cb must be valid!
/// NB: all pointers are invalidated by next call to register_addon or get_addon_info
/// \return false if index is out of range

inline bool get_addon_info_idx(int index, addon_info_t *info)
{
  return callui(ui_addons, 3, index, info).cnd;
}

//@} ui_addons_funcs

#endif

//---------------------------------------------------------------------------
//      S T R I N G   F U N C T I O N S
//---------------------------------------------------------------------------
/// \defgroup str_funcs Functions: strings
/// functions that manipulate strings
//@{

/// Add space characters to the colored string so that its length will be at least
/// 'len' characters. Don't trim the string if it is longer than 'len'.
/// \param str      pointer to colored string to modify (may not be nullptr)
/// \param bufsize  size of the buffer with the string
/// \param len      the desired length of the string
/// \return pointer to the end of input string

idaman THREAD_SAFE char *ida_export add_spaces(char *str, size_t bufsize, ssize_t len);


/// Remove trailing space characters from a string.
/// \param str  pointer to string to modify (may be nullptr)
/// \return pointer to input string

idaman THREAD_SAFE char *ida_export trim(char *str);


/// Skip whitespaces in the string.
/// \return pointer to first non-whitespace char in given string

idaman THREAD_SAFE const char *ida_export skip_spaces(const char *ptr);
inline char *skip_spaces(char *ptr) ///< \copydoc skip_spaces()
  { return CONST_CAST(char*)(skip_spaces((const char *)ptr)); }

/// Map strings to integer values - see strarray()
struct strarray_t
{
  int code;
  const char *text;
};


/// \defgroup CLNL_ line cleanup flags
/// Passed as 'flags' parameter to qcleanline()
//@{
#define CLNL_RTRIM      (1 << 0) ///< Remove trailing space characters.
#define CLNL_LTRIM      (1 << 1) ///< Remove leading space characters.
#define CLNL_FINDCMT    (1 << 2) ///< Search for the comment symbol everywhere in the line, not only at the beginning

#define CLNL_TRIM       (CLNL_RTRIM|CLNL_LTRIM)
//@}

/// Performs some cleanup operations to a line.
/// \param buf      string to modify
/// \param cmt_char character that denotes the start of a comment:
///                 - the entire text is removed if the line begins with
///                   this character (ignoring leading spaces)
///                 - all text after (and including) this character is removed
///                   if flag CLNL_FINDCMT is set
/// \param flags    a combination of \ref CLNL_. defaults to CLNL_TRIM
/// \return length of line

idaman THREAD_SAFE ssize_t ida_export qcleanline(
        qstring *buf,
        char cmt_char='\0',
        uint32 flags=CLNL_TRIM|CLNL_FINDCMT);


/// Find a line with the specified code in the ::strarray_t array.
/// If the last element of the array has code==0 then it is considered as the default entry.  \n
/// If no default entry exists and the code is not found, strarray() returns "".

idaman THREAD_SAFE const char *ida_export strarray(const strarray_t *array, size_t array_size, int code);


/// Convert linear address to UTF-8 string

idaman size_t ida_export ea2str(char *buf, size_t bufsize, ea_t ea);

//---------------------------------------------------------------------------
//      C O N V E R S I O N S
//---------------------------------------------------------------------------
/// \defgroup conv Functions: string conversion
/// functions that convert between string encodings
//@{

/// Convert linear address to UTF-8 string
inline bool ea2str(qstring *out, ea_t ea)
{
  char tmp[MAXSTR];
  if ( ea2str(tmp, sizeof(tmp), ea) <= 0 )
    return false;
  *out = tmp;
  return true;
}


/// Convert string to linear address.
/// Tries to interpret the string as:                                                                       \n
/// 1) "current IP" keyword if supported by assembler (e.g. "$" in x86)                                     \n
/// 2) segment:offset expression, where "segment" may be a name or a fixed segment register (e.g. cs, ds)   \n
/// 3) just segment name/register (translated to segment's start address)                                   \n
/// 4) a name in the database (or debug name during debugging)                                              \n
/// 5) +delta or -delta, where numerical 'delta' is added to or subtracted from 'screen_ea'                 \n
/// 6) if all else fails, try to evaluate 'str' as an IDC expression
///
/// \param out[out]  the buffer to put the result
/// \param str       string to parse
/// \param screen_ea the current address in the disassembly/pseudocode view
/// \return success

idaman bool ida_export str2ea(ea_t *out, const char *str, ea_t screen_ea=BADADDR);


/// Same as str2ea() but possibly with some steps skipped.
/// \param[out] out  the buffer to put the result
/// \param str       string to parse
/// \param screen_ea the current address in the disassembly/pseudocode view
/// \param flags     see \ref S2EAOPT_
/// \return success

idaman bool ida_export str2ea_ex(ea_t *out, const char *str, ea_t screen_ea=BADADDR, int flags=0);

/// \defgroup S2EAOPT_ String to address conversion flags
/// passed as 'flags' parameter to str2ea_ex()
//@{
#define S2EAOPT_NOCALC 0x00000001 ///< don't try to interpret string as IDC (or current extlang) expression
//@}

/// Convert a number in C notation to an address.
/// decimal: 1234         \n
/// octal: 0123           \n
/// hexadecimal: 0xabcd   \n
/// binary: 0b00101010
/// \param[out] out the buffer to put the result
/// \param      str the string to parse

idaman bool ida_export atoea(ea_t *out, const char *str);

#ifndef SWIG

/// Convert segment selector to UTF-8 string

idaman size_t ida_export stoa(qstring *out, ea_t from, sel_t seg);

/// Convert UTF-8 string to segment selector.
/// \retval 0 fail
/// \retval 1 ok (hex)
/// \retval 2 ok (segment name or reg)

idaman int ida_export atos(sel_t *seg, const char *str);


#define MAX_NUMBUF (128+8) ///< 16-byte value in binary base (0b00101010...)


/// Get the number of UTF-8 characters required to represent
/// a number with the specified number of bytes and radix.
/// \param nbytes  if 0, use default number of bytes, usually 4 or 8 depending on __EA64__
/// \param radix   if 0, use default radix, usually 16

idaman size_t ida_export b2a_width(int nbytes, int radix);


/// Convert number to UTF-8 string (includes leading zeroes).
/// \param x        value to convert
/// \param buf      output buffer
/// \param bufsize  size of output buffer
/// \param nbytes   1, 2, 3, or 4
/// \param radix    2, 8, 10, or 16
/// \return size of resulting string

idaman size_t ida_export b2a32(char *buf, size_t bufsize, uint32 x, int nbytes, int radix);


/// Same as b2a32(), but can handle 'nbytes' = 8

idaman size_t ida_export b2a64(char *buf, size_t bufsize, uint64 x, int nbytes, int radix);



/// Get max number of UTF-8 characters required to represent
/// a given type of value, with a given size (without leading zeroes).
/// \param nbytes  size of number
/// \param flag    should be one of FF_ for #MS_0TYPE
/// \param n       if 1, shr 'flag' by 4

idaman size_t ida_export btoa_width(int nbytes, flags64_t flag, int n);


/// Same as b2a32(), but will generate a string without any leading zeroes.
/// Can be used to output some numbers in the instructions.

idaman size_t ida_export btoa32(char *buf, size_t bufsize, uint32 x, int radix=0);


/// 64-bit equivalent of btoa32()

idaman size_t ida_export btoa64(char *buf, size_t bufsize, uint64 x, int radix=0);


/// 128-bit equivalent of btoa32()

idaman size_t ida_export btoa128(char *buf, size_t bufsize, uint128 x, int radix=0);

#ifdef __EA64__
#define b2a b2a64
#define btoa btoa64
#define atob atob64
#else
#define b2a b2a32    ///< shortcut for number->string conversion, see b2a32()
#define btoa btoa32  ///< shortcut for number->string conversion, see btoa32()
#define atob atob32  ///< shortcut for string->number conversion, see atob32()
#endif


/// Convert instruction operand immediate number to UTF-8.
/// This is the main function to output numbers in the instruction operands.         \n
/// It prints the number with or without the leading zeroes depending on the flags.  \n
/// This function is called from out_value(). Please use out_value() if you can.

idaman size_t ida_export numop2str(
        char *buf,
        size_t bufsize,
        ea_t ea,
        int n,
        uint64 x,
        int nbytes,
        int radix=0);


/// Convert UTF-8 to a number using the current assembler formats.
/// e.g. for ibmpc, '12o' is octal, '12h' is hex, etc.
/// \return success

idaman bool ida_export atob32(uint32 *x, const char *str);


/// 64-bit equivalent of atob32()

idaman bool ida_export atob64(uint64 *x, const char *str); // returns 1-ok


/// Pretty-print a size.
/// The output is concise and easy to grasp, like 23k, 1.2G, or 8.56T.
/// Values >= 1000TB are printed as "infty".
/// \param buf the output buffer
/// \param bufsize size of the output buffer. 8 is enough.
/// \param value value to print
/// \return number of bytes stored into buf.
///         if the buffer is too small, the output will be truncated.

idaman size_t ida_export pretty_print_size(char *buf, size_t bufsize, uint64 value);

/// Parse a pretty-printed size.
/// This performs the reverse operation of pretty_print_size()
/// \param out the resulting value
/// \param in the formatted string
/// \return success

idaman bool ida_export parse_pretty_size(uint64 *out, const char *in);


/// Auxiliary function.
/// Print displacement to a name (+disp or -disp) in the natural radix
/// \param buf   output buffer to append to
/// \param disp  displacement to output. 0 leads to no modifications
/// \param tag   whether to output color tags

idaman void ida_export append_disp(qstring *buf, adiff_t disp, bool tag=true);


/// Convert RADIX50 -> UTF-8.
/// \param p  pointer to UTF-8 string
/// \param r  pointer to radix50 string
/// \param k  number of elements in the input string                      \n
///           (element of radix50 string is a word)                       \n
///           (element of UTF-8   string is a character)
/// \return   number of elements left unprocessed in the input string,    \n
///           because the input string contains unconvertible elements.   \n
///           0-ok, all elements are converted

idaman THREAD_SAFE int ida_export r50_to_asc(char *p, const ushort *r, int k);


/// Convert UTF-8 -> RADIX50 (see r50_to_asc())

int THREAD_SAFE asc_to_r50(ushort *r, const char *p, int k);


//@} Conversion functions
//@} String functions

//----------------------------------------------------------------------------
/// \cond
#define IS_BUTTONCB_T(v)      (std::is_same<decltype(v), buttoncb_t>::value)
#define IS_FORMCHGCB_T(v)     (std::is_same<decltype(v), formchgcb_t>::value)
#define IS_TEXTCTRL_INFO_T(v) (std::is_base_of<textctrl_info_t, std::remove_reference<decltype(v)>::type>::value)
#define IS_CHOOSER_BASE_T(v)  (std::is_base_of<chooser_base_t, std::remove_reference<decltype(v)>::type>::value)

/// \endcond

#endif // SWIG

//----------------------------------------------------------------------------
/// \defgroup winkeys Compatibility Windows virtual keys
/// compatibility windows virtual keys to use in plugins which are not Qt aware. (check the #CVH_QT_AWARE flag)
/// these keys are provided for compilation of older plugins that use windows virtual keys on all platforms.
/// those constants are currently passed to cli_t->keydown and customview/CVH_KEYDOWN handlers.
//@{
#define IK_CANCEL              0x03
#define IK_BACK                0x08
#define IK_TAB                 0x09
#define IK_CLEAR               0x0C
#define IK_RETURN              0x0D
#define IK_SHIFT               0x10
#define IK_CONTROL             0x11
#define IK_MENU                0x12
#define IK_PAUSE               0x13
#define IK_CAPITAL             0x14
#define IK_KANA                0x15
#define IK_ESCAPE              0x1B
#define IK_MODECHANGE          0x1F
#define IK_SPACE               0x20
#define IK_PRIOR               0x21
#define IK_NEXT                0x22
#define IK_END                 0x23
#define IK_HOME                0x24
#define IK_LEFT                0x25
#define IK_UP                  0x26
#define IK_RIGHT               0x27
#define IK_DOWN                0x28
#define IK_SELECT              0x29
#define IK_PRINT               0x2A
#define IK_EXECUTE             0x2B
#define IK_SNAPSHOT            0x2C
#define IK_INSERT              0x2D
#define IK_DELETE              0x2E
#define IK_HELP                0x2F
#define IK_LWIN                0x5B
#define IK_RWIN                0x5C
#define IK_APPS                0x5D
#define IK_SLEEP               0x5F
#define IK_NUMPAD0             0x60
#define IK_NUMPAD1             0x61
#define IK_NUMPAD2             0x62
#define IK_NUMPAD3             0x63
#define IK_NUMPAD4             0x64
#define IK_NUMPAD5             0x65
#define IK_NUMPAD6             0x66
#define IK_NUMPAD7             0x67
#define IK_NUMPAD8             0x68
#define IK_NUMPAD9             0x69
#define IK_MULTIPLY            0x6A
#define IK_ADD                 0x6B
#define IK_SEPARATOR           0x6C
#define IK_SUBTRACT            0x6D
#define IK_DECIMAL             0x6E
#define IK_DIVIDE              0x6F
#define IK_F1                  0x70
#define IK_F2                  0x71
#define IK_F3                  0x72
#define IK_F4                  0x73
#define IK_F5                  0x74
#define IK_F6                  0x75
#define IK_F7                  0x76
#define IK_F8                  0x77
#define IK_F9                  0x78
#define IK_F10                 0x79
#define IK_F11                 0x7A
#define IK_F12                 0x7B
#define IK_F13                 0x7C
#define IK_F14                 0x7D
#define IK_F15                 0x7E
#define IK_F16                 0x7F
#define IK_F17                 0x80
#define IK_F18                 0x81
#define IK_F19                 0x82
#define IK_F20                 0x83
#define IK_F21                 0x84
#define IK_F22                 0x85
#define IK_F23                 0x86
#define IK_F24                 0x87
#define IK_NUMLOCK             0x90
#define IK_SCROLL              0x91
#define IK_OEM_FJ_MASSHOU      0x93
#define IK_OEM_FJ_TOUROKU      0x94
#define IK_LSHIFT              0xA0
#define IK_RSHIFT              0xA1
#define IK_LCONTROL            0xA2
#define IK_RCONTROL            0xA3
#define IK_LMENU               0xA4
#define IK_RMENU               0xA5
#define IK_BROWSER_BACK        0xA6
#define IK_BROWSER_FORWARD     0xA7
#define IK_BROWSER_REFRESH     0xA8
#define IK_BROWSER_STOP        0xA9
#define IK_BROWSER_SEARCH      0xAA
#define IK_BROWSER_FAVORITES   0xAB
#define IK_BROWSER_HOME        0xAC
#define IK_VOLUME_MUTE         0xAD
#define IK_VOLUME_DOWN         0xAE
#define IK_VOLUME_UP           0xAF
#define IK_MEDIA_NEXT_TRACK    0xB0
#define IK_MEDIA_PREV_TRACK    0xB1
#define IK_MEDIA_STOP          0xB2
#define IK_MEDIA_PLAY_PAUSE    0xB3
#define IK_LAUNCH_MAIL         0xB4
#define IK_LAUNCH_MEDIA_SELECT 0xB5
#define IK_LAUNCH_APP1         0xB6
#define IK_LAUNCH_APP2         0xB7
#define IK_OEM_1               0xBA
#define IK_OEM_PLUS            0xBB
#define IK_OEM_COMMA           0xBC
#define IK_OEM_MINUS           0xBD
#define IK_OEM_PERIOD          0xBE
#define IK_OEM_2               0xBF
#define IK_OEM_3               0xC0
#define IK_OEM_4               0xDB
#define IK_OEM_5               0xDC
#define IK_OEM_6               0xDD
#define IK_OEM_7               0xDE
#define IK_OEM_102             0xE2
#define IK_PLAY                0xFA
#define IK_ZOOM                0xFB
#define IK_OEM_CLEAR           0xFE
//@}

/// \defgroup CB_ Form callback special values
//@{
enum cb_id
{
  CB_INIT = -1,
  CB_YES  = -2,       // the user pressed 'Yes' button
  CB_CLOSE = -3,      // the form is closed by the window manager
                      // (usually by pressing the small 'x' at the title)
  CB_INVISIBLE = -4,  // corresponds to ui_widget_invisible
  CB_DESTROYING = -5, // the actual widget tree is being destroyed
  CB_NO = -6,         // the user pressed 'No' button
  CB_CANCEL = -7,     // the user pressed 'Cancel' button or Esc
};
//@}

#ifndef SWIG
//-------------------------------------------------------------------------
inline void place_t__serialize(const place_t *_this, bytevec_t *out)
{
  out->pack_dd(_this->lnnum);
}

//-------------------------------------------------------------------------
inline bool place_t__deserialize(place_t *_this, const uchar **pptr, const uchar *end)
{
  if ( *pptr >= end )
    return false;
  _this->lnnum = unpack_dd(pptr, end);
  return true;
}
#endif


#ifndef NO_OBSOLETE_FUNCS
/// Deprecated. Please use ACTION_DESC_LITERAL_* instead.
#define ACTION_DESC_LITERAL(name, label, handler, shortcut, tooltip, icon)\
  { sizeof(action_desc_t), name, label, handler, &PLUGIN, shortcut, tooltip, icon, ADF_OT_PLUGIN }

inline void get_user_strlist_options(strwinsetup_t *out)
{
  callui(ui_obsolete_get_user_strlist_options, out);
}
inline bool del_idc_hotkey(const char *hotkey)
{
  return callui(ui_obsolete_del_idckey, hotkey).cnd;
}
idaman void ida_export ida_checkmem(const char *file, int line);
#endif

#endif // __KERNWIN_HPP
