---
title: Trusted Path Routing
abbrev: trust-path
docname: draft-voit-rats-trustworthy-path-routing-03
stand_alone: true
ipr: trust200902
area: Security
wg: RATS Working Group
kw: Internet-Draft
cat: std
pi:
  toc: yes
  tocdepth: 3
  sortrefs: yes
  symrefs: yes

author:
- ins: E. Voit
  name: Eric Voit
  org: Cisco Systems, Inc.
  abbrev: Cisco
  email: evoit@cisco.com
  street: 8135 Maple Lawn Blvd
  city: Fulton
  code: '20759'
  region: Maryland
  country: USA
- ins: C. Gaddam
  name: Chennakesava Reddy Gaddam
  org: Cisco Systems, Inc.
  abbrev: Cisco
  email: chgaddam@cisco.com
  street: Cessna Business Park, Kadubeesanahalli
  city: Bangalore
  code: '560103'
  region: Karnataka
  country: India
- ins: G. Fedorkow
  name: Guy C. Fedorkow
  org: Juniper Networks
  abbrev: Juniper
  email: gfedorkow@juniper.net
  street: 10 Technology Park Drive
  city: Westford
  code: '01886'
  region: Massachusetts
  country: USA
- ins: H. Birkholz
  name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany

normative:
  RFC8639: event-stream-subscription
  RFC6021: Common YANG Data Types

  attestation-results:  
    target: https://tools.ietf.org/html/draft-voit-rats-attestation-results-00
    title: "Attestation Results for Connectivity"
    date: 2021-04-26
  
  crypto-types:  
    target: https://datatracker.ietf.org/doc/draft-ietf-netconf-crypto-types/
    title: "Common YANG Data Types for Cryptography"
    date: 2020-05-20

  RATS-Arch:  
    target: https://tools.ietf.org/html/draft-ietf-rats-architecture-02
    title: "Remote Attestation Procedures Architecture"
    date: 2020-03-06

  RATS-YANG:  
    target: https://datatracker.ietf.org/doc/draft-ietf-rats-yang-tpm-charra/
    title: "A YANG Data Model for Challenge-Response-based Remote Attestation Procedures using TPMs"
    date: 2020-06-23

  TPM1.2:
    target: https://trustedcomputinggroup.org/resource/tpm-main-specification/
    title: "TPM 1.2 Main Specification"
    author:
      -
        ins: TCG
        name: Trusted Computing Group
    date: 2003-10-02
  TPM2.0:
    target: https://trustedcomputinggroup.org/resource/tpm-library-specification/
    title: "TPM 2.0 Library Specification"
    author:
      -
        ins: TCG
        name: Trusted Computing Group
    date: 2013-03-15



informative:
  RFC3748: EAP

  RATS-Interactions:  
    target: https://ietf-rats.github.io/draft-birkholz-rats-reference-interaction-model/draft-birkholz-rats-reference-interaction-model.html#section-7
    title: "Reference Interaction Models for Remote Attestation Procedures"
    date: 2020-06-24
  
  stream-subscription:  
    target: https://datatracker.ietf.org/doc/draft-birkholz-rats-network-device-subscription
    title: "Attestation Event Stream Subscription"
    date: 2020-06-03
  
  I-D.ietf-lsr-flex-algo: FlexAlgo
  
  RATS-Device:
    target: https://datatracker.ietf.org/doc/draft-ietf-rats-tpm-based-network-device-attest
    title: "Network Device Remote Integrity Verification"

  MACSEC:
    target: https://1.ieee802.org/security/802-1ae/ 
    title: "802.1AE: MAC Security (MACsec)"
    author:
      -
        ins: M. Seaman
        name: Mick Seaman
    date: 2006-01-01
  IEEE-802.1X:
    target: https://standards.ieee.org/standard/802_1X-2010.html
    title: "802.1AE: MAC Security (MACsec)"
    author:
      -
        ins: G. Parsons
        name: Glenn Parsons
    date: 2020-01-01

--- abstract

There are end-users who believe encryption technologies like IPSec alone are insufficient to protect the confidentiality of their highly sensitive traffic flows.  These end-users want their flows to traverse devices which have been freshly appraised and verified for trustworthiness. This specification describes Trusted Path Routing.  Trusted Path Routing protects sensitive flows as they transit a network by forwarding traffic to/from sensitive subnets across network devices recently appraised as trustworthy.  

--- middle

#  Introduction 

There are end-users who believe encryption technologies like IPSec alone are insufficient to protect the confidentiality of their highly sensitive traffic flows.   These customers want their highly sensitive flows to be transported over only network devices recently verified as trustworthy. 

By using a router's embedded TPM based cryptoprocessors in conjunction with the Remote Attestation context established by {{attestation-results}}, a network provider can identify potentially compromised devices as well as potentially exploitable (or even exploited) vulnerabilities.  Using this knowledge, it is then possible to redirect sensitive flows around these devices while other remediations are potentially considered by Network Operations.  

Trusted Path Routing allows the establishing Trusted Topologies which only include trust-verified network devices.  Membership in a Trusted Topology is established and maintained via an exchange of Stamped Passports at the link layer between peering network devices. As links to Attesting Devices are appraised as meeting at least a minimum set of formally defined Trustworthiness Claims, the links are then included as members of this Trusted Topology.  Routing protocols are then used to propagate topology state throughout a network.  

IP Packets to and from end-user designated Sensitive Subnets are then forwarded into this Trusted Topology at each network boundary.  This is done by an end user identifying sensitive IP subnets where flows with applications using these IP subnets need enhanced privacy guarantees. Trusted Path Routing passes flows to/from these Sensitive Subnets over a Trusted Topology able to meet these guarantees.  The Trusted Topology itself consists of the interconnection of network devices where each potentially transited device has been verified as achieving a specific set of Trustworthiness Claims during its most recent trustworthiness appraisal. Interesting sets of Trustworthiness Claims might be marketed to end-users in the following ways:

* all transited devices have booted with known hardware and firmware
* all transited devices are from a specific set of vendors and are running known software containing the latest patches
* no guarantees provided


# Terminology

## Terms
The following terms are imported from {{RATS-Arch}}: 
Attester, Evidence, Passport, Relying Party, and Verifier. 

The following terms are impored from {{attestation-results}}:
Trustworthiness Claim, Trustworthiness Vector, AR-augmented Evidence

Newly defined terms for this document:

Attested Device --
: a network connected Attester where a Verifier's most recent appraisal of Evidence has returned a Trustworthiness Vector.   

Stamped Passport --
: AR-augmented Evidence which can take two forms.  First if the Attester uses a TPM2, the the Verifier Proof-of-Freshness includes the \<clock\>, \<reset-counter\>, \<restart-counter\> and \<safe\> objects from a recent TPM2 quote made by that Attester, and the Relying Party Proof-of-Freshness is returned along with the timeticks as objects embedded within the most recent TPM quote signed by the same TPM2. Second, if the Attester uses a TPM1.2: the Verifier Proof-of-Freshness includes a global timestamp from that Verifier, and the Relying Party Proof-of-Freshness is embedded within a more recent TPM quote signed by the same TPM Attesting Environment. 

Sensitive Subnet --
: an IP address range where IP packets to or from that range desire confidentially guarantees beyond those of non-identified subnets.  In practice, flows to or from a Sensitive Subnet must only have their IP headers and encapsulated payloads accessible/visible only by Attested Devices supporting one or more Trustworthiness Vectors. 

Transparently-Transited Device --
: a network device within an network domain where any packets originally passed into that network domain are completely opaque on that network device at Layer 3 and above. 

Trusted Topology --
: a topology which includes only Attested Devices and Transparently-Transited Devices.


## Requirements Notation

{::boilerplate bcp14}



# Implementation Prerequisites 

The specification is a valid instance of {{attestation-results}}.  This specification works under the following protocol and preconfiguration prerequisite assumptions:

* All Attested Devices support the TPM remote attestation profile as laid out in {{RATS-Device}}.
* One or more Verifier A's as defined in {{attestation-results}} 'Interaction Model' continuously appraise each of the Attested Devices in a network domain, and these Verifiers return the Attestation Results back to each originating Attested Device.
* The Attested Devices are connected via link layer protocols such as {{MACSEC}} or {{IEEE-802.1X}}.
* Each Attester can pass a Stamped Passport to a Relying Party / Verifier B as defined in {{attestation-results}} 'Interaction Model' within {{-EAP}} over that link layer protocol.
* A Trusted Topology such as {{-FlexAlgo}} exists in an IGP domain for the forwarding of Sensitive Subnet traffic.  This Topology will carry traffic across a set of Attested Devices which currently meet at a defined set of Trustworthiness Vectors.
* A Relying Party is able to use mechanisms such as {{-FlexAlgo}}'s affinity to include/exclude links as part of the Trusted Topology based on the appraisal of a Stamped Passport.
* Customer designated Sensitive Subnets and their requested Trustworthiness Vectors have been identified and associated with external interfaces to/from Attested Devices at the edge of a network. Traffic to a Sensitive Subnet can be passed into the Trusted Topology by the Attested Device.
* Relying Party/Verifier B trusts information signed by Verifier A.  Verifier B has also been pre-provisioned with certificates or public keys necessary to confirm that Stamped Passports came from Verifier A.


# End-to-end Solution

## Network Topology Assembly

To be included in a Trusted Topology, Stamped Passports are shared between Attested Devices (such as routers).  Upon receiving and appraising the Stamped Passport as part of link layer authentication, the Relying Party Attested Device decides if this link should be added as an active adjacency for a particular Trusted Topology.  In {{fig-topology}} below, this might be done by applying an Appraisal Policy for Attestation Results which requires any Attesting Device be most recently appraised with the Trustworthiness Claim 'hw-authentic'.  If Attested Device 'x' has been appraised with 'hw-verification-fail' is would not become part of the Trustworthy Topology. 

When enough links have been successfully added, the Trusted Topology will support edge-to-edge forwarding as routing protocols flood the adjacency information across the network domain.

~~~
               .------------.                .----------.
               | Attested   |                | Edge     |       
 .----------.  | Device 'x' |                | Attested |    
 | Attested |  |            |                | Device   |  
 | Device   |  |            |                |          |  
 |          |  |        trust>---------------<no_trust  |
 |  no_trust>--<trust       |  .----------.  |          |---Sensitive
 |          |  '------------'  |     trust>==<trust     |   Subnet 
 |     trust>==================<trust     |  |          |    
 '----------'                  |          |  '----------' 
                               | Attested | 
                               | Device   | 
                               '----------' 
~~~
{: #fig-topology title="Trusted Path Topology Assembly"}


As the process described above repeats over time across the set of links within a network domain, Trusted Topologies can be extended and maintained. Traffic to and from Sensitive Subnets is then identified at the edges of the network domain and passed into this Trusted Topology.  Traffic exchanged with Sensitive Subnets can then be forwarded across that Trusted Topology from all edges of the network domain.


## Attestation Information Flows

Critical to the establishment and maintenance of a Trusted Topology is the Stamped Passport.  A Stamped Passport is comprised of Evidence from both an Attester and a Verifier.  A Stamped Passport is a valid type of AR-augmented evidence as described in {{attestation-results}}.

Stamped Passports are exchanged between adjacent network devices over a link layer protocols like 802.1x or MACSEC.  As both sides of a link may need might need to appraise the other, independent Stamped Passports will often be transmitted from either side of the link.  Additionally, as link layer protocols will continuously re-authenticate the link, this allows for fresh Stamped Passports to be constantly appraised by either side of the connection. 

Each Stamped Passport will include the most recent Verifier provided Attestation Results, as well as the most recent TPM Quote for that Attester.  Upon receiving this information as part of link layer authentication, the Relying Party Router appraises the results and decides if this link should be added to a Trusted Topology. 

{{fig-timing}} describes this flow of information using the time definitions described in {{RATS-Arch}}, and the information flows defined in Section 7 of {{RATS-Interactions}}.  This figure is also a valid embodiment of the "Interaction Model" described within {{attestation-results}}.  (Note that the Relying Party must also be an Attested Device in order to attract Sensitive Subnet traffic which may flow from the Attester.)

~~~                                                     
  .------------------.
  | Attester         |
  |                  |
  | (Attested Device |
  |   / Router)      |                           .------------------.
  |  .-------------. |                           | Relying Party    |
  |  | TPM based   | |                           |   / Verifier B   |
  |  | Attesting   | |           .----------.    |                  |
  |  | Environment | |           | Verifier |    | (Attested Device |
  |  '-------------' |           |     A    |    |   / Router)      |
  '------------------'           '----------'    '------------------'
        time(VG)                       |                 |  
          |<------nonce--------------time(NS)            |   
          |                            |                 |  
 time(EG)(1)------Evidence------------>|                 |  
          |                          time(RG)            | 
          |<------Attestation Results-(2)                | 
          ~                            ~                 ~ 
        time(VG')?                     |                 | 
          ~                            ~                 ~
          |<------nonce---------------------------------(3)time(NS') 
          |                            |                 |   
time(EG')(4)------Stamped Passport---------------------->| 
          |                            |   time(RG',RA')(5)
                                                        (6)
                                                         ~
                                                      time(RX')  
~~~
{: #fig-timing title="Trusted Path Timing"}

To summarize {{fig-timing}} above, Evidence about a specific Attester is generated.  Some subset of this evidence will be in the form of PCR quotes which are signed by a TPM that exists as the Attester's Attesting Environment. This Evidence will be delibered to and appraised by Verifier A.  Verifier A will then appraise the Attester and give it a Trustworthiness Vector.  This Trustworthiness Vector is then signed by Verifier A and be returned as Attestation Results to the Attester. Later, when a request comes in from a Relying Party, the Attester assembles and returns a Stamped Passport.  The Stamped Passport contains all the information necessary for Verifier B to appraise the most recent Trustworthiness Vector of the Attester.  Based on the Verifier B appraisal, the link will be included or not in a Trusted Topology maintained on the Relying Party.

More details on the mechanisms used in the construction, verification, and transmitting of the Stamped Passport are listed below.  These numbers match to both the numbered steps of {{fig-timing}} and numbered steps described in Section 3 of {{attestation-results}}:

### Step 1

Evidence about and Attester is generated.  A portion of this Evidence will include a PCR quote signed by a TPM private LDevID key that exists within the Attester's TPM based Attesting Environment.  The Attester sends a signed TPM Quote which includes PCR measurements to Verifier A at time(EG).  

There are two alternatives for Verifier A to acquire this signed Evidence:

* Subscription to the \<attestation\> stream defined in {{stream-subscription}}.  Note: this method is recommended as it will minimize the interval between when a PCR change is made in a TPM, and when the PCR change appraisal is incorporated within a subsequent Stamped Passport.  
* Periodic polling of RPC \<tpm20-challenge-response-attestation\> or the RPC \<tpm12-challenge-response-attestation\> which are defined in {{RATS-YANG}}.

### Step 2

Verifier A appraises the Evidence from Step 1.  A portion of this appraisal process will follow the appraisal process flow described below. This appraisal process MUST be able to set at least the following set of Trustworthiness Claims from {{attestation-results}}: 'hw-authentic', 'hw-verification-fail', 'tee-identity-verified', 'tee-identity-fail', 'executables-verified', and 'executables-fail'.  The establishment of a Trustworthiness Vector uses the following {{verifier-A}} logic on the Verifier:

~~~~
Start: TPM Quote Received, log received, or appraisal timer expired
       for the the Attesting network device.

Appraisal 0: set Trustworthiness Vector = Null

Appraisal 1: Is there sufficient fresh signed evidence to appraise?
  yes - No action
  no -  Go to End
   
Appraisal 2: Appraise Hardware Integrity
  if not evaluated, or insufficient data to conclude: take no action
   else if (hw-authentic) - push onto vector
    else (if hw-verification-fail) - push onto vector, go to End

Appraisal 3: Appraise attester identity
  if not evaluated, or insufficient data to conclude: take no action
   else if (tee-identity-verified) - push onto vector
    else if (tee-identity-fail) - push onto vector
  
Appraisal 4: Appraise executable loaded 
  if not evaluated, or insufficient data to conclude: take no action
    else if (executables-verified) - push onto vector
     else (if executables-fail) - push onto vector, go to End

Appraisal 5: a Verifier has the option of appraising and asserting
  additional non-standard Trustworthiness Claims.  It can do so here. 

End
~~~~
{: #verifier-A title="Verifier A Appraisal Flow"}


After the appraisal and generation of the Trustworthiness Vector, the following are assembled as the set of Attestation Results from this particular appraisal cycle:

(2.1) the Public Attestation Key which was used to validate the TPM Quote of Step 1.  This is encoded by \<public-key\>, \<public-key-format\>, and \<public-key-algorithm-type\>.

(2.2) the appraised Trustworthiness Vector of the Attester as calculated in {{verifier-A}}

(2.3) the PCR state information from the TPM Quote of (1) plus the time information associated with the TPM Quote of (1).  Specifically if the Attester has a TPM2, then the values of the TPM PCRs are included (i.e., \<TPM2B_DIGEST\>, \<tpm20-hash-algo\>, and \<pcr-index\>), as are the timing counters from the TPM (i.e., \<clock\>, \<reset-counter\>, \<restart-counter\>, and \<safe\>). Likewise if the Attester has a TPM1.2, the TPM PCR values of the \<pcr-index\> and \<pcr-value\> are included.  Timing information comes from the Verifier itself via the \<timestamp\> object.

(2.4) a Verifier A signature across (2.1) though (2.3). This signature is encoded by \<verifier-signature\>, \<verifier-key-algorithm-type\>, and \<verifier-signature-key-name\>.

Immediately subsequent to each Verifier appraisal cycle of an Attester, these Attestation Results MUST be pushed to the Attesting Router.   This is done via a daatstore write to the following YANG model on the Attester.  A YANG tree showing the relevant YANG objects is below.  The YANG model describing each of these objects is described later in the document.  Note however that although the YANG model shows the specific objects which are needed, the specific set of objects needs to be encoded in CDDL.  This makes the payload going over TLS more efficient.  Look for this encoding in a new version of the draft which is coming shortly.

~~~ YANG
module: ietf-trustworthiness-claims
  +--rw attestation-results!
     +--rw (tpm-specification-version)?
        +--:(tpm20-attestation-results-cddl) {taa:tpm20}?
        |  +--rw trustworthiness-vector*              identityref
        |  +--rw tpm20-pcr-selection* [tpm20-hash-algo]
        |  |  +--rw tpm20-hash-algo    identityref
        |  |  +--rw pcr-index*         tpm:pcr
        |  +--rw TPM2B_DIGEST                         binary
        |  +--rw clock                                uint64
        |  +--rw reset-counter                        uint32
        |  +--rw restart-counter                      uint32
        |  +--rw safe                                 boolean
        |  +--rw appraisal-timestamp
        |  |       yang:date-and-time
        |  +--rw verifier-algorithm-type              identityref
        |  +--rw verifier-signature                   binary
        |  +--rw verifier-certificate-keystore-ref
        |          tpm:certificate-name-ref
        +--:(tpm12-attestation-results-cddl) {taa:TPM12}?
           +--rw trustworthiness-vector*              identityref
           +--rw pcr-index*                           pcr
           +--rw tpm12-pcr-value*                     binary
           +--rw TPM12-quote-timestamp
           |       yang:date-and-time
           +--rw appraisal-timestamp
           |       yang:date-and-time
           +--rw verifier-algorithm-type              identityref
           +--rw verifier-signature                   binary
           +--rw verifier-certificate-keystore-ref
                   tpm:certificate-name-ref

(Do we want the Verifier signature across the keystore-ref?)
~~~
{: #fig-results-tree title="Attestation Results Tree"}


### Step 3

At time(NS') some form of time-based freshness (such as a nonce or Epoch Handle {{RATS-Interactions}}) will be generated in a way which makes it available to the Relying Party.   Soon after time(NS'), a Relying Party will make a Link Layer authentication request to an Attester via a either {{MACSEC}} or {{IEEE-802.1X}}.  This connection request MUST expect the return of {{-EAP}} credentials from the Attester.  

### Step 4

Upon receipt of the Link Layer request from Step 3, a Stamped Passport is generated and sent to the Relying Party.  The Stamped Passport MUST include the following:

(4.1) The Attestation Results from Step 2   

(4.2) New signed, verifiably fresh PCR measurements from time(EG'), which incorporates the freshness information known by the Relying Party from Step 3.  If it is a nonce, the freshness information will have been delivered as part of the link layer connection request in Steps 3.

Stamped Passports contain following objects, defined in this document via YANG.  A subsequent draft will convert the objects below into CDDL format so that the objects can efficiently be passed over EAP.  

If an Attester includes a TPM2, these YANG objects are:
 
~~~ 
    +---n tpm20-stamped-passport
       +--ro attestation-results
       |  +--ro trustworthiness-vector*              identityref
       |  +--ro tpm20-pcr-selection* [tpm20-hash-algo]
       |  |  +--ro tpm20-hash-algo    identityref
       |  |  +--ro pcr-index*         tpm:pcr
       |  +--ro TPM2B_DIGEST                         binary
       |  +--ro clock                                uint64
       |  +--ro reset-counter                        uint32
       |  +--ro restart-counter                      uint32
       |  +--ro safe                                 boolean
       |  +--ro appraisal-timestamp
       |  |       yang:date-and-time
       |  +--ro verifier-algorithm-type              identityref
       |  +--ro verifier-signature                   binary
       |  +--ro verifier-certificate-keystore-ref
       |          tpm:certificate-name-ref
       +--ro tpm20-quote
          +--ro TPMS_QUOTE_INFO     binary
          +--ro quote-signature?    binary
          +--ro certificate-name    certificate-name-ref

~~~
{: #fig-tpm2-passport title="YANG Tree for a TPM2 Stamped Passport"}

And if the Attester is a TPM1.2, the YANG object are:

~~~
    +---n tpm12-stamped-passport
       +--ro attestation-results
       |  +--ro trustworthiness-vector*              identityref
       |  +--ro pcr-index*                           pcr
       |  +--ro tpm12-pcr-value*                     binary
       |  +--ro TPM12-quote-timestamp
       |  |       yang:date-and-time
       |  +--ro appraisal-timestamp
       |  |       yang:date-and-time
       |  +--ro verifier-algorithm-type              identityref
       |  +--ro verifier-signature                   binary
       |  +--ro verifier-certificate-keystore-ref
       |          tpm:certificate-name-ref
       +--ro tpm12-quote
          +--ro TPM_QUOTE2?         binary
          +--ro certificate-name    certificate-name-ref

~~~
{: #fig-tpm12-passport title="YANG Tree for a TPM1.2 Stamped Passport"}

With either of these passport formats, if the TPM quote is verifiably fresh, then the state of the Attester can be appraised by a network peer.

Note that with {{MACSEC}} or {{IEEE-802.1X}}, Step 3 plus Step 4 will repeat periodically independently of any subsequent iteration Steps 1 and Step 2. This allows for periodic reauthentication of the link layer in a way not bound to the updating of Verifier A's Attestation Results. 

    
### Step 5

Upon receipt of the Stamped Passport generated in Step 4, the Relying Party appraises this Stamped Passport as per its Appraisal Policy for Attestation Results. The result of this application will determine how the Stamped Passport will impact adjacencies within a Trusted Topology.  The decision process is as follows:

(5.1) Verify that (4.2) includes the freshness context from Step 3.

(5.2) Use a local certificate to validate the signature (4.1).  
  
(5.3) Verify that the hash from (4.2) matches (4.1)

(5.4) Use the identity of (2.1) to validate the signature of (4.2). 

(5.5) Failure of any steps (5.1) through (5.4) means the link does not meet minimum validation criteria, therefore appraise the link as having a null Verifier B Trustworthiness Vector.  Jump to Step 6. 

(5.6) Compare the time(EG) TPM state to the time(EG') TPM state
    
* If TPM2.0
    
    1. If the \<TPM2B_DIGEST\>, \<reset-counter\>, \<restart-counter\> and \<safe\> are equal between the Attestation Results and the TPM Quote at time(EG') then Relying Party can accept (2.1) as the link's Trustworthiness Vector. Jump to Step 6.   
    2. If the \<reset-counter\>, \<restart-counter\> and \<safe\> are equal between the Attestation Results and the TPM Quote at time(EG'), and the \<clock\> object from time(EG') has not incremented by an unacceptable number of seconds since the Attestation Result, then Relying Party can accept (2.1) as the link's Trustworthiness Vector. Jump to Step 6.) 
    3. Assign the link a null Trustworthiness Vector.
       
* If TPM1.2
        
    1. If the \<pcr-index\>'s and \<tpm12-pcr-value\>'s are equal between the Attestation Results and the TPM Quote at time(EG'), then Relying Party can accept (2.1) as the link's Trustworthiness Vector. Jump to step (6).   
    2. If the time hasn't incremented an unacceptable number of seconds from the Attestation Results \<timestamp\> and the system clock of the Relying Party, then Relying Party can accept (2.1) as the link's Trustworthiness Vector. Jump to step 6.) 
    3. Assign the link a null Trustworthiness Vector.
        
(5.7) Assemble the Verifier B Trustworthiness Vector
    
1. Copy Verifier A Trustworthiness Vector to Verifier B Trustworthiness Vector
2. Prune any Trustworthiness Claims the Relying Party doesn't accept from this Verifier.


### Step 6

After the Trustworthiness Vector has been validated or reset, based on the link's Trustworthiness Vector, the Relying Party adjusts the link affinity of the corresponding ISIS {{-FlexAlgo}} topology.  ISIS will then replicate the link state across the IGP domain.  Traffic will then avoid links which do not have a qualifying Trustworthiness Vector.



{: #YANG-Module} 
# YANG Module

This YANG module imports modules from {{RATS-YANG}}, {{crypto-types}} and {{RFC6021}}. 


~~~~ YANG
<CODE BEGINS> ietf-trustworthiness-claims@2021-05-12.yang
{::include /media/sf_rats/ietf-trustworthiness-claims@2021-05-12.yang}
<CODE ENDS>
~~~~ 


# Security Considerations

Verifiers are limited to the Evidence available for appraisal from a Router.   Although the state of the art is improving, some exploits may not be visible via Evidence.

Only security measurements which are placed into PCRs are capable of being exposed via TPM Quote at time(EG').

Successful attacks on an Verifier have the potential of affecting traffic on the Trusted Topology.

For Trusted Path Routing, links which are part of the FlexAlgo are visible across the entire IGP domain.  Therefore a compromised device will know when it is being bypassed.

Access control for the objects in {{fig-results-tree}} should be tightly controlled so that it becomes difficult for the Stamped Passport to become a denial of service vector.

--- back

# Acknowledgements

Peter Psenak, Shwetha Bhandari, Adwaith Gautham, Annu Singh, Sujal Sheth, Nancy Cam Winget, and Ned Smith. 

#  Change Log

\[THIS SECTION TO BE REMOVED BY THE RFC EDITOR.\]

v02-v03

* Integrated {{attestation-results}} as prerequisite context.
* Totally rearranged content.  But there were not meaningful process changes.
* Redid YANG model, and highlighted CDDL needs.

v01-v02

* Minor tweaks such as renaming and removal of a few trustworthiness-claims

v00-v01

* Minor tweaks

v02-v00 of draft-voit-rats-trustworthy-path-routing-00

* file rename was due to an IETF tool submission glitch
* The Attester's AIK is included within the Stamped Passport.  This eliminates the need to provision to AIK certificate on the Relying Party.
* Removed Centralized variant
* Added timing diagram, and moved content around to match

v01-v02 of draft-voit-rats-trusted-path-routing 

* Extracted the attestation stream, and placed into draft-birkholz-rats-network-device-subscription
* Introduced the Trustworthiness Vector

v00-v01 of draft-voit-rats-trusted-path-routing

* Move all FlexAlgo terminology to allow passport definition to be more generic.
* Edited Figure 1 so that (4) points to the egress router.
* Added text freshness mechanisms, and articulated configured subscription support. 
* Minor YANG model clarifications.
* Added a few open questions which Frank thinks interesting to work.

# Open Questions

(1) When there is no available Trusted Topology?

Do we need functional requirements on how to handle traffic to/from Sensitive Subnets when no Trusted Topology exists between IGP edges?  The network typically can make this unnecessary.    For example it is possible to construct a local IPSec tunnel to make untrusted devices appear as Transparently-Transited Devices.  This way Secure Subnets could be tunneled between FlexAlgo nodes where an end-to-end path doesn't currently exist.  However there still is a corner case where all IGP egress points are not considered sufficiently trustworthy.

(2) Extension of the Stamped Passport?

Format of the reference to the 'verifier-certificate-name' based on WG desire to include more information in the Stamped Passport.  Also we need to make sure that the keystore referenced names are globally unique, else we will need to include a node name in the object set.

(3) Encoding of objects in CDDL.  A Verifier will want to sign encoded objects rather than YANG structures.  It is most efficient to encode the Attestation Results once on the Verifier, and push these down via a YANG model to the Attester.
