package main

import (
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/networkfirewall"
	"github.com/aws/aws-sdk-go/service/networkfirewall/networkfirewalliface"
)

type Client struct {
	ec2Client ec2iface.EC2API
	firewallClient networkfirewalliface.NetworkFirewallAPI
}
var wait = 120 * time.Second
var wait2 = 360 * time.Second
func main() {

	creds := credentials.NewStaticCredentials(os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), os.Getenv("AWS_SESSION_TOKEN"))
	region := "us-east-1"


	ec2Client := ec2.New(session.New(&aws.Config{
		Region:      &region,
		Credentials: creds,
	}))
	//create firewall client
	firewallClient := networkfirewall.New(session.Must(session.NewSession()), &aws.Config{
		Region:      &region,
		Credentials: creds,
	})
    awsClient := Client{
       ec2Client, 	
	   firewallClient,
	}
	//Create VPC
	Vpc := awsClient.CreateVPC("10.0.0.0/16")
	//Create Internet Gateway
	IG :=awsClient.CreateInternetGateway(Vpc)
	//Create Public Subnet
	PublicSubnet := awsClient.CreateSubnet("10.0.0.0/24", Vpc)
	//Create Private Subnet
	PrivateSubnet := awsClient.CreateSubnet("10.0.1.0/24", Vpc)
	//Create Firewall Subnet
	FirewallSubnet := awsClient.CreateSubnet("10.0.2.0/24", Vpc)
	//Create PublicSubnet Route Table
	PublicRT := awsClient.CreateRouteTable(Vpc, PublicSubnet)
	//Create PrivateSubnet Route Table
	PrivateRT := awsClient.CreateRouteTable(Vpc, PrivateSubnet)
	//Create FirewallSubnet Route Table
	FirewallRT := awsClient.CreateRouteTable(Vpc, FirewallSubnet)
	//Create IGW Route Table
	IgRT :=awsClient.CreateRouteTableIG(Vpc, IG)
	//Create NAT Gateway
	NatGateway := awsClient.CreateNatGateway(PublicSubnet)

	//Create route 0.0.0.0/0 in PrivateRT for NatGateway
	awsClient.CreateRoute("0.0.0.0/0", *NatGateway.NatGateway.NatGatewayId, PrivateRT)
	fmt.Println("Successfully Created a route 0.0.0.0/0 to NatGateway in Private Subnet")
	//Create route 0.0.0.0/0 in FirewallSubnet for IG
	awsClient.CreateRoute("0.0.0.0/0", *IG.InternetGateway.InternetGatewayId, FirewallRT)
	fmt.Println("Successfully Created a route 0.0.0.0/0 to IGW in Firewall Subnet")

	//Create Firewall
	Firewall := awsClient.CreateFirewall(FirewallSubnet, Vpc)
	//Describe Firewall
	DescribeFirewall :=awsClient.DescribeFirewall(Firewall)
	//Create route 0.0.0.0/0 in PublicRT for FirewallEndpoint
	awsClient.CreateRouteToFirewall("0.0.0.0/0", *DescribeFirewall.FirewallStatus.SyncStates[*FirewallSubnet.Subnet.AvailabilityZone].Attachment.EndpointId, PublicRT)
	fmt.Println("Successfully route 0.0.0.0/0 to the Firewall Endpoint in PublicRT ")
	//Create route 10.0.0.0/24 in IgRt to FirewallEndpoint
	awsClient.CreateRouteToFirewall("10.0.0.0/24", *DescribeFirewall.FirewallStatus.SyncStates[*FirewallSubnet.Subnet.AvailabilityZone].Attachment.EndpointId, IgRT)
	fmt.Println("Successfully route 10.0.0.0/24 to the Firewall Endpoint in IgRT ")

}

func (c Client)CreateVPC (CidrBlock string) (ec2.CreateVpcOutput){
	VPCinput := &ec2.CreateVpcInput{
		CidrBlock: aws.String(CidrBlock),
	}

	VPCresult, err := c.ec2Client.CreateVpc(VPCinput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}

	fmt.Println("Successfully created a vpc")
	//Enable DNSHostname
	DNSHostnameinput := &ec2.ModifyVpcAttributeInput{
		EnableDnsHostnames: &ec2.AttributeBooleanValue{
			Value: aws.Bool(true),
		},
		VpcId: aws.String(*VPCresult.Vpc.VpcId),
	}

	_, err = c.ec2Client.ModifyVpcAttribute(DNSHostnameinput)
	return *VPCresult
}

func (c Client)CreateInternetGateway (Vpc ec2.CreateVpcOutput) (ec2.CreateInternetGatewayOutput){
	IGinput := &ec2.CreateInternetGatewayInput{}
	IGresult, err := c.ec2Client.CreateInternetGateway(IGinput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}

	fmt.Println("Successfully created IG")
	//Attach the InternetGateway to the VPC
	IGAttachinput := &ec2.AttachInternetGatewayInput{
		InternetGatewayId: aws.String(*IGresult.InternetGateway.InternetGatewayId),
		VpcId:             aws.String(*Vpc.Vpc.VpcId),
	}
	 _ , err = c.ec2Client.AttachInternetGateway(IGAttachinput)
	 if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}
	fmt.Println("Successfully attached IG to VPC")

	return *IGresult
}

func (c Client)CreateSubnet(CidrBlock string, Vpc ec2.CreateVpcOutput) (ec2.CreateSubnetOutput){
	Subnetinput := &ec2.CreateSubnetInput{
		CidrBlock: aws.String(CidrBlock),
		VpcId:     aws.String(*Vpc.Vpc.VpcId),
	}
	Subnet, err := c.ec2Client.CreateSubnet(Subnetinput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}

	return *Subnet
}

func (c Client) CreateRouteTable (Vpc ec2.CreateVpcOutput, Subnet ec2.CreateSubnetOutput)(ec2.CreateRouteTableOutput){
	RouteTable1input := &ec2.CreateRouteTableInput{
		VpcId: aws.String(*Vpc.Vpc.VpcId),
	}

	RT, err := c.ec2Client.CreateRouteTable(RouteTable1input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}
	Associateinput := &ec2.AssociateRouteTableInput{
		RouteTableId: aws.String(*RT.RouteTable.RouteTableId),
		SubnetId:     aws.String(*Subnet.Subnet.SubnetId),
	}
	_ , err = c.ec2Client.AssociateRouteTable(Associateinput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}
	return *RT
}

func (c Client) CreateRouteTableIG (Vpc ec2.CreateVpcOutput, IG ec2.CreateInternetGatewayOutput)(ec2.CreateRouteTableOutput){
	RouteTable1input := &ec2.CreateRouteTableInput{
		VpcId: aws.String(*Vpc.Vpc.VpcId),
	}

	RT, err := c.ec2Client.CreateRouteTable(RouteTable1input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}
	Associateinput := &ec2.AssociateRouteTableInput{
		RouteTableId: aws.String(*RT.RouteTable.RouteTableId),
		GatewayId:     aws.String(*IG.InternetGateway.InternetGatewayId),
	}
	_ , err = c.ec2Client.AssociateRouteTable(Associateinput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}
	return *RT
}
func (c Client)CreateNatGateway( Subnet ec2.CreateSubnetOutput) (ec2.CreateNatGatewayOutput){
	EIPinput := &ec2.AllocateAddressInput{
		Domain: aws.String("vpc"),
	}

	EIPresult, err := c.ec2Client.AllocateAddress(EIPinput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}
	NGinput := &ec2.CreateNatGatewayInput{
		AllocationId: aws.String(*EIPresult.AllocationId),
		SubnetId:     aws.String(*Subnet.Subnet.SubnetId),
	}

	NGresult, err := c.ec2Client.CreateNatGateway(NGinput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}
	time.Sleep(wait)
	fmt.Println("Successfully create a NAT Gateway")
	return *NGresult
}
func (c Client) CreateRoute(CidrBlock string, GatewayID string, RouteTable ec2.CreateRouteTableOutput){
	Ruleinput := &ec2.CreateRouteInput{
		DestinationCidrBlock: aws.String(CidrBlock),
		GatewayId:            aws.String(GatewayID),
		RouteTableId:         aws.String(*RouteTable.RouteTable.RouteTableId),
	}

	_, err := c.ec2Client.CreateRoute(Ruleinput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}

}
func (c Client) CreateFirewall(FirewallSubnet ec2.CreateSubnetOutput, Vpc ec2.CreateVpcOutput)(networkfirewall.CreateFirewallOutput){
	RuleGroupinput := &networkfirewall.CreateRuleGroupInput{
		Capacity:      aws.Int64(100),
		RuleGroupName: aws.String("test-firewall"),
		Type:          aws.String("STATEFUL"),
		RuleGroup: &networkfirewall.RuleGroup{
			RulesSource: &networkfirewall.RulesSource{
				RulesSourceList: &networkfirewall.RulesSourceList{
					GeneratedRulesType: aws.String("DENYLIST"),
					TargetTypes:        []*string{aws.String("TLS_SNI")},
					Targets:            []*string{aws.String(".quay.io"), aws.String(".amazonaws.com"), aws.String("api.openshift.com"), aws.String(".redhat.io")},
				},
			},
		},
	}

	statefulRuleGroup, err := c.firewallClient.CreateRuleGroup(RuleGroupinput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}
	fmt.Println("Successfully creates a Stateful Rule Group")
	time.Sleep(wait)
	
	FirewallPolicyInput := &networkfirewall.CreateFirewallPolicyInput{
		Description: aws.String("test"),
		FirewallPolicyName:  aws.String("testPolicy"),
		FirewallPolicy: &networkfirewall.FirewallPolicy{
			StatefulRuleGroupReferences: []*networkfirewall.StatefulRuleGroupReference{&networkfirewall.StatefulRuleGroupReference{
				ResourceArn: statefulRuleGroup.RuleGroupResponse.RuleGroupArn},
			},
			StatelessDefaultActions: []*string{aws.String("aws:forward_to_sfe")},
			StatelessFragmentDefaultActions: []*string{aws.String("aws:forward_to_sfe")},
		},
	}
	testFirewallPolicy, err := c.firewallClient.CreateFirewallPolicy(FirewallPolicyInput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}
	fmt.Println("Successfully created a Firewall Policy")

		testFirewallInput := &networkfirewall.CreateFirewallInput{
		FirewallName:      aws.String("testFirewall"),
		FirewallPolicyArn: testFirewallPolicy.FirewallPolicyResponse.FirewallPolicyArn,
		SubnetMappings: []*networkfirewall.SubnetMapping{&networkfirewall.SubnetMapping{
			SubnetId: FirewallSubnet.Subnet.SubnetId},
		},
		VpcId: aws.String(*Vpc.Vpc.VpcId),
	}

	Firewall, err := c.firewallClient.CreateFirewall(testFirewallInput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}
	fmt.Println("Successfully created a Firewall. Having to wait a long time for the endpoint to be ready!")
	time.Sleep(wait2)

	return *Firewall

}
func (c Client) DescribeFirewall (Firewall networkfirewall.CreateFirewallOutput)(networkfirewall.DescribeFirewallOutput){
	DescribeFirewallInput := &networkfirewall.DescribeFirewallInput{
		FirewallName	:aws.String(*Firewall.Firewall.FirewallName),
	}
	DescribeFirewall, err := c.firewallClient.DescribeFirewall(DescribeFirewallInput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}
	return *DescribeFirewall
}

func (c Client) CreateRouteToFirewall(CidrBlock string, VPCEndpointId string, RouteTable ec2.CreateRouteTableOutput){
	Ruleinput := &ec2.CreateRouteInput{
		DestinationCidrBlock: aws.String(CidrBlock),
		VpcEndpointId:            aws.String(VPCEndpointId),
		RouteTableId:         aws.String(*RouteTable.RouteTable.RouteTableId),
	}

	_, err := c.ec2Client.CreateRoute(Ruleinput)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			fmt.Println(err.Error())
		}
	}

}
