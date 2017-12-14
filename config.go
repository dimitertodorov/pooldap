package pooldap

type LdapConfig struct {
	Host                 string            `mapstructure:"host"`
	Port                 int               `mapstructure:"port"`
	Attributes           []string          `mapstructure:"attributes"`
	AttributeMap         map[string]string `mapstructure:"attribute_map"`
	EmailAttributes      []string          `mapstructure:"email_attributes"`
	Base                 string            `mapstructure:"base"`
	BindDN               string            `mapstructure:"bind_dn"`
	BindPassword         string            `mapstructure:"bind_password"`
	GroupFilter          string            `mapstructure:"group_filter"`
	GroupNameAttribute   string            `mapstructure:"group_name_attribute"`
	GroupMemberAttribute string            `mapstructure:"group_member_attribute"`
	ServerName           string            `mapstructure:"server_name"`
	UserFilter           string            `mapstructure:"user_filter"`
	Uid                  string            `mapstructure:"uid"`
	UseSSL               bool              `mapstructure:"use_ssl"`
	InsecureSkipVerify   bool              `mapstructure:"insecure_skip_verify"`
	SkipTLS              bool              `mapstructure:"skip_tls"`
	LogLevel             string            `mapstructure:"log_level"`
}
