from typing import List
import xml.etree.ElementTree as ET


SCHEMA = "{http://www.icasi.org/CVRF/schema/vuln/1.1}"
SEARCH_TERM = "gitlab"
XML_FILE_PATH = "C:\\Users\\conno\\OneDrive\\Documents\\code\\battelle\\xml_parser\\allitems-cvrf-year-2022.xml"

class Note:
    def __init__(
        self, description: str = None, published: str = None, modified: str = None
    ) -> None:
        self.description = description
        self.published = published
        self.modified = modified

    def __repr__(self) -> str:
        s = ""
        if self.description:
            s += f"{self.description}"
        if self.published:
            s += f", Published: {self.published}"
        if self.modified:
            s += f", Modified: {self.modified}"
        return s


class Reference:
    def __init__(self, url: str = None, description: str = None) -> None:
        self.url = url
        self.description = description

    def __repr__(self) -> str:
        s = ""
        if self.description:
            s += f"{self.description}"
        if self.url:
            s += f" {{{self.url}}}"
        return s


class Vulnerability:
    def __init__(
        self, notes: List[str], refs: List[str], cve: str = "", title: str = ""
    ) -> None:
        self.cve = cve
        self.title = title
        self.notes = notes
        self.refs = refs

    def __repr__(self) -> str:
        notes_str = "".join([str(note) for note in self.notes])
        ref_str = ", ".join([str(ref) for ref in self.refs])
        return (
            f"Vulnerability Number: {self.cve}\n"
            + f"Title: {self.title}\n"
            + f"Notes: {notes_str}\n"
            + f"References: {ref_str}\n"
        )


def main():
    """Scans a given XML document with an assume schema and prints them out"""
    vulnerabilties = parse()
    for vuln in vulnerabilties:
        print(vuln)


def parse():
    """Walks through the XML tree to find nodes described as Vulnerabilities and appends them to a list.

    Returns:
        List[Vulnerability]: A list of Vulnerability objects 
    """
    tree = ET.parse(XML_FILE_PATH)
    root = tree.getroot()
    vulnerabilities = []
    for child in root:
        if "Vulnerability" in child.tag:
            vuln = scan_vuln(child)
            if vuln:
                vulnerabilities.append(vuln)
    return vulnerabilities


def scan_vuln(vuln_element: ET.Element):
    """Given an Element, attempts to construct a Vulnerability object and returns only those which reference the given SEARCH_TERM

    Args:
        vuln_element (ET.Element): An Element object found via walking the XML tree

    Returns:
        Vulnerability: A Vulnerability object whose References contain the SEARCH_TERM, otherwise None 
    """
    vuln = Vulnerability([], [])
    for sub_element in vuln_element:
        element_name = sub_element.tag[len(SCHEMA) :]
        if element_name == "Title":
            vuln.title = sub_element.text
        if element_name == "CVE":
            vuln.cve = sub_element.text
        if element_name == "Notes":
            new_note = scan_notes(sub_element)
            vuln.notes.append(new_note)
        if element_name == "References":
            for ref in sub_element:
                vuln.refs.append(scan_refs(ref))
    if references_gitlab(vuln):
        return vuln
    else:
        return None


def scan_notes(element: ET.Element):
    """Given an Element tagged as "Notes", builds a Note object by walking through its ordinals

    Args:
        element (ET.Element): An Element that is tagged as "Notes"

    Returns:
        Note: A Note object containing the text from the available ordinals
    """
    new_note = Note()
    for i in range(len(element)):
        if i == 0:
            new_note.description = element[i].text
        if i == 1:
            new_note.published = element[i].text
        if i == 2:
            new_note.modified = element[i].text
    return new_note


def scan_refs(element: ET.Element):
    """Given an Element tagged as "Reference", builds a Reference object by walking through its sub-elements

    Args:
        element (ET.Element): An Element tagged as "Reference"

    Returns:
        Reference: A Reference object containing the URL and description from the sub-elements
    """
    new_ref = Reference()
    for detail in element:
        if "URL" in detail.tag:
            new_ref.url = detail.text
        if "Description" in detail.tag:
            new_ref.description = detail.text
    return new_ref


def references_gitlab(vuln: Vulnerability):
    """Given a Vulnerability object, asserts that the SEARCH_TERM exists within the Reference object's URL

    Args:
        vuln (Vulnerability): The Vulnerability object whose References will be checked against the SEARCH_TERM

    Returns:
        Boolean: True if the SEARCH_TERM is found, else False
    """
    for ref in vuln.refs:
        if SEARCH_TERM in ref.url.lower() or SEARCH_TERM in ref.description.lower():
            return True


if __name__ == "__main__":
    main()
