package auth

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

type loginForm struct {
	Action       *url.URL
	Method       string
	Values       url.Values
	UsernameName string
	PasswordName string
}

func parseLoginForm(reader io.Reader, pageURL *url.URL) (loginForm, error) {
	document, err := html.Parse(reader)
	if err != nil {
		return loginForm{}, fmt.Errorf("parse Cognito login page: %w", err)
	}

	var formNodes []*html.Node
	var findForms func(*html.Node)
	findForms = func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == "form" {
			formNodes = append(formNodes, node)

			return
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			findForms(child)
		}
	}

	findForms(document)
	if len(formNodes) == 0 {
		return loginForm{}, fmt.Errorf("Cognito login page contains no form")
	}

	for _, formNode := range formNodes {
		form, parseErr := parseFormNode(formNode, pageURL)

		if parseErr == nil {
			return form, nil
		}
	}

	return loginForm{}, fmt.Errorf("Cognito login page contains no form with username and password fields")
}

func parseFormNode(formNode *html.Node, pageURL *url.URL) (loginForm, error) {
	var err error
	form := loginForm{
		Method: httpMethodAttribute(formNode),
		Values: make(url.Values),
	}

	action := attribute(formNode, "action")
	if action == "" {
		form.Action = pageURL
	} else {
		form.Action, err = pageURL.Parse(action)
		if err != nil {
			return loginForm{}, fmt.Errorf("parse login form action: %w", err)
		}
	}

	var collect func(*html.Node)
	collect = func(node *html.Node) {
		if node.Type == html.ElementNode {
			switch node.Data {
			case "input":
				collectInput(&form, node)

			case "textarea":
				if name := attribute(node, "name"); name != "" {
					form.Values.Add(name, textContent(node))
				}

			case "select":
				collectSelect(&form, node)
			}
		}

		for child := node.FirstChild; child != nil; child = child.NextSibling {
			collect(child)
		}
	}

	collect(formNode)

	if form.UsernameName == "" || form.PasswordName == "" {
		return loginForm{}, fmt.Errorf("form does not contain username and password fields")
	}

	return form, nil
}

func collectInput(form *loginForm, node *html.Node) {
	name := attribute(node, "name")
	if name == "" {
		return
	}

	typeName := strings.ToLower(attribute(node, "type"))
	if typeName == "submit" || typeName == "button" || typeName == "image" || typeName == "reset" {
		return
	}
	if (typeName == "checkbox" || typeName == "radio") && attribute(node, "checked") == "" {
		return
	}

	form.Values.Add(name, attribute(node, "value"))
	if typeName == "password" {
		form.PasswordName = name
	}

	if form.UsernameName == "" && (typeName == "email" || typeName == "text" || strings.EqualFold(name, "username")) {
		form.UsernameName = name
	}
}

func collectSelect(form *loginForm, node *html.Node) {
	name := attribute(node, "name")
	if name == "" {
		return
	}

	var selected string
	var findOption func(*html.Node)

	findOption = func(child *html.Node) {
		if selected != "" {
			return
		}
		if child.Type == html.ElementNode && child.Data == "option" {
			if attribute(child, "selected") != "" || selected == "" {
				selected = attribute(child, "value")
			}
		}

		for nested := child.FirstChild; nested != nil; nested = nested.NextSibling {
			findOption(nested)
		}
	}

	findOption(node)
	form.Values.Add(name, selected)
}

func attribute(node *html.Node, name string) string {
	for _, attr := range node.Attr {
		if attr.Key == name {
			return attr.Val
		}
	}

	return ""
}

func httpMethodAttribute(node *html.Node) string {
	method := strings.ToUpper(attribute(node, "method"))
	if method == "" {
		return "GET"
	}

	return method
}

func textContent(node *html.Node) string {
	var content strings.Builder
	var collect func(*html.Node)

	collect = func(child *html.Node) {
		if child.Type == html.TextNode {
			content.WriteString(child.Data)
		}

		for nested := child.FirstChild; nested != nil; nested = nested.NextSibling {
			collect(nested)
		}
	}

	collect(node)

	return content.String()
}
