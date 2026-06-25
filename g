cf.create_distribution_tenant(
    Name="poopy",
    DistributionId=DISTRIBUTION_ID,
    ConnectionGroupId="matthew",
    Domains=["poopy.tld.com"],
    Enabled=True,
    Customizations={
        'Certificate': {
            'Arn': cert_arn,
            'SslSupportMethod': 'sni-only',
            'MinimumProtocolVersion': 'TLSv1.2_2021'
        }
    },
)
