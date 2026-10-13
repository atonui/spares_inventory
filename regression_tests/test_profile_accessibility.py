"""Static semantic contracts; these do not claim rendered/mobile verification."""
from html.parser import HTMLParser
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class Elements(HTMLParser):
    def __init__(self,text):
        super().__init__();self.elements=[];self.feed(text)
    def handle_starttag(self,tag,attrs):self.elements.append((tag,dict(attrs)))
def elements():return Elements((ROOT/'static/profile.html').read_text()).elements

def test_every_editable_control_has_an_associated_label():
    nodes=elements();labels={a['for'] for t,a in nodes if t=='label' and 'for' in a}
    controls=[a for t,a in nodes if t in ('input','select') and a.get('type') not in ('hidden','submit')]
    assert controls and all(a.get('id') in labels for a in controls)

def test_profile_tabs_expose_selected_state_and_control_matching_panels():
    nodes=elements();tabs=[a for t,a in nodes if a.get('role')=='tab'];panels={a.get('id'):a for t,a in nodes if a.get('role')=='tabpanel'}
    assert len(tabs)==2 and len(panels)==2
    for tab in tabs:
        assert ':aria-selected' in tab and ':tabindex' in tab
        assert panels[tab['aria-controls']]['aria-labelledby']==tab['id']
    assert any(a.get('role')=='tablist' for t,a in nodes)


def test_profile_has_a_named_main_landmark_and_status_feedback():
    nodes=elements();headings={a.get('id') for t,a in nodes if t=='h1'}
    assert any(t=='main' and a.get('aria-labelledby') in headings for t,a in nodes)
    assert any(a.get('role')=='alert' for t,a in nodes)
    assert any(a.get('role')=='status' for t,a in nodes)
