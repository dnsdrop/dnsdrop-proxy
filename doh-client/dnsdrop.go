package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/m13253/dns-over-https/doh-client/selector"
	"github.com/m13253/dns-over-https/json-dns"
	"github.com/miekg/dns"
)

func (c *Client) generateRequestDNSDrop(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, isTCP bool, upstream *selector.Upstream) *DNSRequest {
	obj := map[string]interface{}{
		"_rcode":   r.Rcode,
		"_opcode":  r.Opcode,
		"_qdcount": len(r.Question),
		"_id":      r.Id,
		"_qr":      r.Response,
		"_aa":      r.Authoritative,
		"_tc":      r.Truncated,
		"_rd":      r.RecursionDesired,
		"_cd":      r.CheckingDisabled,
		"_ra":      r.RecursionAvailable,
		"_ad":      r.AuthenticatedData,
		"_question": []map[string]interface{}{
			{
				"_rr_question": true,
				"_rr_class":    r.Question[0].Qclass,
				"_rr_type":     r.Question[0].Qtype,
				"_owner": map[string]interface{}{
					"_data": r.Question[0].Name,
					"_type": LDNS_RDF_TYPE_DNAME,
				},
			},
		},
	}

	j, err := json.Marshal(obj)
	if err != nil {
		log.Println(err)

		reply := jsonDNS.PrepareReply(r)
		reply.Rcode = dns.RcodeServerFailure
		w.WriteMsg(reply)

		return &DNSRequest{
			err: err,
		}
	}

	requestURL := upstream.URL + "/_dns/"
	requestDAT := strings.NewReader(string(j))

	req, err := http.NewRequest(http.MethodPost, requestURL, requestDAT)
	//req.Close = true

	if err != nil {
		log.Println(err, req)

		reply := jsonDNS.PrepareReply(r)
		reply.Rcode = dns.RcodeServerFailure
		w.WriteMsg(reply)

		return &DNSRequest{
			err: err,
		}
	}

	req = req.WithContext(ctx)

	c.httpClientMux.RLock()
	resp, err := c.httpClient.Do(req)
	//client := new(http.Client)
	//resp, err := client.Do(req)
	c.httpClientMux.RUnlock()

	if err != nil {
		log.Println(err, req, resp)

		reply := jsonDNS.PrepareReply(r)
		reply.Rcode = dns.RcodeServerFailure
		w.WriteMsg(reply)

		return &DNSRequest{
			err: err,
		}
	}

	udpSize := uint16(512)

	if opt := r.IsEdns0(); opt != nil {
		udpSize = opt.UDPSize()
	}

	return &DNSRequest{
		response:        resp,
		reply:           jsonDNS.PrepareReply(r),
		udpSize:         udpSize,
		currentUpstream: upstream.URL,
	}
}

type DNSDropRDF struct {
	Data string `json:"_data"`
	Type int    `json:"_type"`
}

type DNSDropRR struct {
	Class       uint16       `json:"_rr_class"`
	Type        uint16       `json:"_rr_type"`
	RDCount     uint16       `json:"_rd_count"`
	TTL         uint32       `json:"_ttl"`
	Owner       DNSDropRDF   `json:"_owner"`
	RDataFields []DNSDropRDF `json:"_rdata_fields"`
	IsQuestion  bool         `json:"_rr_question"`
}

type DNSDropRequest struct {
	Rcode      int         `json:"_rcode"`
	Opcode     int         `json:"_opcode"`
	AnswerFrom DNSDropRDF  `json:"_answerfrom"`
	Question   []DNSDropRR `json:"_question"`
	Answer     []DNSDropRR `json:"_answer"`
	Additional []DNSDropRR `json:"_additional"`
	Authority  []DNSDropRR `json:"_authority"`

	Arcount int `json:"_arcount"`
	Nscount int `json:"_nscount"`
	Ancount int `json:"_ancount"`
	Qdcount int `json:"_qdcount"`

	ID uint16 `json:"_id"`
	AD bool   `json:"_ad"`
	RA bool   `json:"_ra"`
	CD bool   `json:"_cd"`
	RD bool   `json:"_rd"`
	TC bool   `json:"_tc"`
	AA bool   `json:"_aa"`
	QR bool   `json:"_qr"`
}

func (c *Client) parseResponseDNSDrop(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, isTCP bool, req *DNSRequest) {

	if req.response.StatusCode != http.StatusOK {
		log.Printf("HTTP error from upstream %s: %s (%v)\n", req.currentUpstream, req.response.Status, req.response)
		req.reply.Rcode = dns.RcodeServerFailure
		contentType := req.response.Header.Get("Content-Type")
		if contentType != "application/dnsdrop-json" && !strings.HasPrefix(contentType, "application/dnsdrop-json;") {
			w.WriteMsg(req.reply)
			return
		}
	}

	body, err := ioutil.ReadAll(req.response.Body)
	req.response.Body.Close()

	if err != nil {
		req.reply.Rcode = dns.RcodeServerFailure
		w.WriteMsg(req.reply)
		return
	}

	var result DNSDropRequest

	json.Unmarshal(body, &result)

	dnsMsg := new(dns.Msg)
	dnsMsg.Rcode = result.Rcode
	dnsMsg.Opcode = result.Opcode
	dnsMsg.Id = r.Id
	dnsMsg.Response = result.QR
	dnsMsg.Authoritative = result.AA
	dnsMsg.Truncated = result.TC
	dnsMsg.RecursionDesired = result.RD
	dnsMsg.CheckingDisabled = result.CD
	dnsMsg.RecursionAvailable = result.RA
	dnsMsg.AuthenticatedData = result.AD

	dnsMsg.Question = make([]dns.Question, 1)
	question := dns.Question{}
	question.Name = result.Question[0].Owner.Data
	question.Qclass = result.Question[0].Class
	question.Qtype = result.Question[0].Type
	dnsMsg.Question[0] = question

	if result.Ancount > 0 {
		dnsMsg.Answer = make([]dns.RR, result.Ancount)

		for i, inRR := range result.Answer {
			rrType, ok := dns.TypeToString[inRR.Type]
			if !ok {
				rrType = "A"
			}

			zone := fmt.Sprintf("%s %d IN %s %s", inRR.Owner.Data, inRR.TTL, rrType, inRR.RDataFields[0].Data)
			dnsRR, _ := dns.NewRR(zone)
			dnsMsg.Answer[i] = dnsRR
		}
	}

	if result.Arcount > 0 {
		dnsMsg.Extra = make([]dns.RR, result.Arcount)

		for i, inRR := range result.Additional {
			rrType, ok := dns.TypeToString[inRR.Type]
			if !ok {
				rrType = "A"
			}

			zone := fmt.Sprintf("%s %d IN %s %s", inRR.Owner.Data, inRR.TTL, rrType, inRR.RDataFields[0].Data)
			dnsRR, err := dns.NewRR(zone)
			if err != nil {
				fmt.Println(err)
			}
			dnsMsg.Extra[i] = dnsRR
		}
	}

	buf, err := dnsMsg.Pack()
	if err != nil {
		log.Println(err)
		req.reply.Rcode = dns.RcodeServerFailure
		w.WriteMsg(req.reply)
		return
	}

	w.Write(buf)
}

const (
	LDNS_RDF_TYPE_NONE = iota
	LDNS_RDF_TYPE_DNAME
	LDNS_RDF_TYPE_INT8
	LDNS_RDF_TYPE_INT16
	LDNS_RDF_TYPE_INT32
	LDNS_RDF_TYPE_A
	LDNS_RDF_TYPE_AAAA
	LDNS_RDF_TYPE_STR
	LDNS_RDF_TYPE_APL
	/** b32 string */
	LDN_RDF_TYPE_B32_EXT
	/** b64 string */
	LDNS_RDF_TYPE_B64
	/** hex string */
	LDNS_RDF_TYPE_HEX
	/** nsec type codes */
	LDNS_RDF_TYPE_NSEC
	/** a RR type */
	LDNS_RDF_TYPE_TYPE
	/** a class */
	LDNS_RDF_TYPE_CLASS
	/** certificate algorithm */
	LDNS_RDF_TYPE_CERT_ALG
	/** a key algorithm */
	LDNS_RDF_TYPE_ALG
	/** unknown types */
	LDNS_RDF_TYPE_UNKNOWN
	/** time (32 bits) */
	LDNS_RDF_TYPE_TIME
	/** period */
	LDNS_RDF_TYPE_PERIOD
	/** tsig time 48 bits */
	LDNS_RDF_TYPE_TSIGTIME
	/** Represents the Public Key Algorithm, HIT and Public Key fields
	  for the HIP RR types.  A HIP specific rdf type is used because of
	  the unusual layout in wireformat (see RFC 5205 Section 5) */
	LDNS_RDF_TYPE_HIP
	/** variable length any type rdata where the length
	  is specified by the first 2 bytes */
	LDNS_RDF_TYPE_INT16_DATA
	/** protocol and port bitmaps */
	LDNS_RDF_TYPE_SERVICE
	/** location data */
	LDNS_RDF_TYPE_LOC
	/** well known services */
	LDNS_RDF_TYPE_WKS
	/** NSAP */
	LDNS_RDF_TYPE_NSAP
	/** ATMA */
	LDNS_RDF_TYPE_ATMA
	/** IPSECKEY */
	LDNS_RDF_TYPE_IPSECKEY
	/** nsec3 hash salt */
	LDNS_RDF_TYPE_NSEC3_SALT
	/** nsec3 base32 string (with length byte on wire */
	LDNS_RDF_TYPE_NSEC3_NEXT_OWNER
	/** 4 shorts represented as 4 * 16 bit hex numbers
	 *  separated by colons. For NID and L64.
	 */
	LDNS_RDF_TYPE_ILNP64
	/** 6 * 8 bit hex numbers separated by dashes. For EUI48. */
	LDNS_RDF_TYPE_EUI48
	/** 8 * 8 bit hex numbers separated by dashes. For EUI64. */
	LDNS_RDF_TYPE_EUI64

	/** A non-zero sequence of US-ASCII letters and numbers in lower case.
	 *  For CAA.
	 */
	LDNS_RDF_TYPE_TAG
	/** A <character-string> encoding of the value field as specified
	 * [RFC1035], Section 5.1., encoded as remaining rdata.
	 * For CAA.
	 */
	LDNS_RDF_TYPE_LONG_STR
	/** Since RFC7218 TLSA records can be given with mnemonics,
	 * hence these rdata field types.  But as with DNSKEYs, the output
	 * is always numeric.
	 */
	LDNS_RDF_TYPE_CERTIFICATE_USAGE
	LDNS_RDF_TYPE_SELECTOR
	LDNS_RDF_TYPE_MATCHING_TYPE
	/* Aliases */
	LDNS_RDF_TYPE_BITMAP = LDNS_RDF_TYPE_NSEC
)
