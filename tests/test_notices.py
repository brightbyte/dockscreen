from dockscreen.screen.notices import Notice, NoticeSeverity
from dockscreen.util import messages


def test_a_notice_reads_as_its_subject_and_text_and_is_marked_by_its_severity():
    notice = Notice("added --cap-drop=ALL", NoticeSeverity.INFO, "service web", "set cap_drop yourself")

    assert str(notice) == "service web: added --cap-drop=ALL"
    assert (notice.subject, notice.text, notice.help) == ("service web", "added --cap-drop=ALL",
                                                          "set cap_drop yourself")
    assert notice.mark is messages.ROUTINE
    assert str(Notice("no subject", NoticeSeverity.WARNING)) == "no subject"
    assert Notice("careful", NoticeSeverity.WARNING).mark is messages.WARN


def test_with_text_with_help_and_about_keep_the_rest_of_a_notice():
    notice = Notice("text", NoticeSeverity.WARNING, "service web", "help")

    assert (notice.with_text("other").subject, notice.with_text("other").severity) == (
        "service web", NoticeSeverity.WARNING)
    assert notice.with_text("other").help == "help"
    assert notice.with_help(None).help is None
    about = notice.about("command line")
    assert str(about) == "command line: service web: text" and about.severity is NoticeSeverity.WARNING
