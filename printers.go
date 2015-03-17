package main

type ReportPrinterFunc func(r Report) error

func xmlPrinter(r Report) error {
	return nil
}

func ReportPrinter(x interface{}) ReportPrinterFunc {
	return nil
}

var (
	ReportPrinters = map[string]ReportPrinterFunc{
		"xml":  ReportPrinter(xmlPrinter),
		"json": ReportPrinter(xmlPrinter),
		"text": ReportPrinter(xmlPrinter),
	}
)
