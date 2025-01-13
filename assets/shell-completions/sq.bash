_sq() {
    local i cur prev opts cmd
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmd=""
    opts=""

    for i in ${COMP_WORDS[@]}
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="sq"
                ;;
            sq,cert)
                cmd="sq__cert"
                ;;
            sq,config)
                cmd="sq__config"
                ;;
            sq,decrypt)
                cmd="sq__decrypt"
                ;;
            sq,download)
                cmd="sq__download"
                ;;
            sq,encrypt)
                cmd="sq__encrypt"
                ;;
            sq,help)
                cmd="sq__help"
                ;;
            sq,inspect)
                cmd="sq__inspect"
                ;;
            sq,key)
                cmd="sq__key"
                ;;
            sq,keyring)
                cmd="sq__keyring"
                ;;
            sq,network)
                cmd="sq__network"
                ;;
            sq,packet)
                cmd="sq__packet"
                ;;
            sq,pki)
                cmd="sq__pki"
                ;;
            sq,sign)
                cmd="sq__sign"
                ;;
            sq,verify)
                cmd="sq__verify"
                ;;
            sq,version)
                cmd="sq__version"
                ;;
            sq__cert,export)
                cmd="sq__cert__export"
                ;;
            sq__cert,import)
                cmd="sq__cert__import"
                ;;
            sq__cert,lint)
                cmd="sq__cert__lint"
                ;;
            sq__cert,list)
                cmd="sq__cert__list"
                ;;
            sq__config,get)
                cmd="sq__config__get"
                ;;
            sq__config,inspect)
                cmd="sq__config__inspect"
                ;;
            sq__config,template)
                cmd="sq__config__template"
                ;;
            sq__config__inspect,network)
                cmd="sq__config__inspect__network"
                ;;
            sq__config__inspect,paths)
                cmd="sq__config__inspect__paths"
                ;;
            sq__config__inspect,policy)
                cmd="sq__config__inspect__policy"
                ;;
            sq__help,cert)
                cmd="sq__help__cert"
                ;;
            sq__help,config)
                cmd="sq__help__config"
                ;;
            sq__help,decrypt)
                cmd="sq__help__decrypt"
                ;;
            sq__help,download)
                cmd="sq__help__download"
                ;;
            sq__help,encrypt)
                cmd="sq__help__encrypt"
                ;;
            sq__help,help)
                cmd="sq__help__help"
                ;;
            sq__help,inspect)
                cmd="sq__help__inspect"
                ;;
            sq__help,key)
                cmd="sq__help__key"
                ;;
            sq__help,keyring)
                cmd="sq__help__keyring"
                ;;
            sq__help,network)
                cmd="sq__help__network"
                ;;
            sq__help,packet)
                cmd="sq__help__packet"
                ;;
            sq__help,pki)
                cmd="sq__help__pki"
                ;;
            sq__help,sign)
                cmd="sq__help__sign"
                ;;
            sq__help,verify)
                cmd="sq__help__verify"
                ;;
            sq__help,version)
                cmd="sq__help__version"
                ;;
            sq__help__cert,export)
                cmd="sq__help__cert__export"
                ;;
            sq__help__cert,import)
                cmd="sq__help__cert__import"
                ;;
            sq__help__cert,lint)
                cmd="sq__help__cert__lint"
                ;;
            sq__help__cert,list)
                cmd="sq__help__cert__list"
                ;;
            sq__help__config,get)
                cmd="sq__help__config__get"
                ;;
            sq__help__config,inspect)
                cmd="sq__help__config__inspect"
                ;;
            sq__help__config,template)
                cmd="sq__help__config__template"
                ;;
            sq__help__config__inspect,network)
                cmd="sq__help__config__inspect__network"
                ;;
            sq__help__config__inspect,paths)
                cmd="sq__help__config__inspect__paths"
                ;;
            sq__help__config__inspect,policy)
                cmd="sq__help__config__inspect__policy"
                ;;
            sq__help__key,approvals)
                cmd="sq__help__key__approvals"
                ;;
            sq__help__key,delete)
                cmd="sq__help__key__delete"
                ;;
            sq__help__key,expire)
                cmd="sq__help__key__expire"
                ;;
            sq__help__key,export)
                cmd="sq__help__key__export"
                ;;
            sq__help__key,generate)
                cmd="sq__help__key__generate"
                ;;
            sq__help__key,import)
                cmd="sq__help__key__import"
                ;;
            sq__help__key,list)
                cmd="sq__help__key__list"
                ;;
            sq__help__key,password)
                cmd="sq__help__key__password"
                ;;
            sq__help__key,revoke)
                cmd="sq__help__key__revoke"
                ;;
            sq__help__key,subkey)
                cmd="sq__help__key__subkey"
                ;;
            sq__help__key,userid)
                cmd="sq__help__key__userid"
                ;;
            sq__help__key__approvals,list)
                cmd="sq__help__key__approvals__list"
                ;;
            sq__help__key__approvals,update)
                cmd="sq__help__key__approvals__update"
                ;;
            sq__help__key__subkey,add)
                cmd="sq__help__key__subkey__add"
                ;;
            sq__help__key__subkey,bind)
                cmd="sq__help__key__subkey__bind"
                ;;
            sq__help__key__subkey,delete)
                cmd="sq__help__key__subkey__delete"
                ;;
            sq__help__key__subkey,expire)
                cmd="sq__help__key__subkey__expire"
                ;;
            sq__help__key__subkey,export)
                cmd="sq__help__key__subkey__export"
                ;;
            sq__help__key__subkey,password)
                cmd="sq__help__key__subkey__password"
                ;;
            sq__help__key__subkey,revoke)
                cmd="sq__help__key__subkey__revoke"
                ;;
            sq__help__key__userid,add)
                cmd="sq__help__key__userid__add"
                ;;
            sq__help__key__userid,revoke)
                cmd="sq__help__key__userid__revoke"
                ;;
            sq__help__keyring,filter)
                cmd="sq__help__keyring__filter"
                ;;
            sq__help__keyring,list)
                cmd="sq__help__keyring__list"
                ;;
            sq__help__keyring,merge)
                cmd="sq__help__keyring__merge"
                ;;
            sq__help__keyring,split)
                cmd="sq__help__keyring__split"
                ;;
            sq__help__network,dane)
                cmd="sq__help__network__dane"
                ;;
            sq__help__network,keyserver)
                cmd="sq__help__network__keyserver"
                ;;
            sq__help__network,search)
                cmd="sq__help__network__search"
                ;;
            sq__help__network,wkd)
                cmd="sq__help__network__wkd"
                ;;
            sq__help__network__dane,generate)
                cmd="sq__help__network__dane__generate"
                ;;
            sq__help__network__dane,search)
                cmd="sq__help__network__dane__search"
                ;;
            sq__help__network__keyserver,publish)
                cmd="sq__help__network__keyserver__publish"
                ;;
            sq__help__network__keyserver,search)
                cmd="sq__help__network__keyserver__search"
                ;;
            sq__help__network__wkd,publish)
                cmd="sq__help__network__wkd__publish"
                ;;
            sq__help__network__wkd,search)
                cmd="sq__help__network__wkd__search"
                ;;
            sq__help__packet,armor)
                cmd="sq__help__packet__armor"
                ;;
            sq__help__packet,dearmor)
                cmd="sq__help__packet__dearmor"
                ;;
            sq__help__packet,decrypt)
                cmd="sq__help__packet__decrypt"
                ;;
            sq__help__packet,dump)
                cmd="sq__help__packet__dump"
                ;;
            sq__help__packet,join)
                cmd="sq__help__packet__join"
                ;;
            sq__help__packet,split)
                cmd="sq__help__packet__split"
                ;;
            sq__help__pki,authenticate)
                cmd="sq__help__pki__authenticate"
                ;;
            sq__help__pki,identify)
                cmd="sq__help__pki__identify"
                ;;
            sq__help__pki,link)
                cmd="sq__help__pki__link"
                ;;
            sq__help__pki,lookup)
                cmd="sq__help__pki__lookup"
                ;;
            sq__help__pki,path)
                cmd="sq__help__pki__path"
                ;;
            sq__help__pki,vouch)
                cmd="sq__help__pki__vouch"
                ;;
            sq__help__pki__link,add)
                cmd="sq__help__pki__link__add"
                ;;
            sq__help__pki__link,authorize)
                cmd="sq__help__pki__link__authorize"
                ;;
            sq__help__pki__link,list)
                cmd="sq__help__pki__link__list"
                ;;
            sq__help__pki__link,retract)
                cmd="sq__help__pki__link__retract"
                ;;
            sq__help__pki__vouch,add)
                cmd="sq__help__pki__vouch__add"
                ;;
            sq__help__pki__vouch,authorize)
                cmd="sq__help__pki__vouch__authorize"
                ;;
            sq__key,approvals)
                cmd="sq__key__approvals"
                ;;
            sq__key,delete)
                cmd="sq__key__delete"
                ;;
            sq__key,expire)
                cmd="sq__key__expire"
                ;;
            sq__key,export)
                cmd="sq__key__export"
                ;;
            sq__key,generate)
                cmd="sq__key__generate"
                ;;
            sq__key,import)
                cmd="sq__key__import"
                ;;
            sq__key,list)
                cmd="sq__key__list"
                ;;
            sq__key,password)
                cmd="sq__key__password"
                ;;
            sq__key,revoke)
                cmd="sq__key__revoke"
                ;;
            sq__key,subkey)
                cmd="sq__key__subkey"
                ;;
            sq__key,userid)
                cmd="sq__key__userid"
                ;;
            sq__key__approvals,list)
                cmd="sq__key__approvals__list"
                ;;
            sq__key__approvals,update)
                cmd="sq__key__approvals__update"
                ;;
            sq__key__subkey,add)
                cmd="sq__key__subkey__add"
                ;;
            sq__key__subkey,bind)
                cmd="sq__key__subkey__bind"
                ;;
            sq__key__subkey,delete)
                cmd="sq__key__subkey__delete"
                ;;
            sq__key__subkey,expire)
                cmd="sq__key__subkey__expire"
                ;;
            sq__key__subkey,export)
                cmd="sq__key__subkey__export"
                ;;
            sq__key__subkey,password)
                cmd="sq__key__subkey__password"
                ;;
            sq__key__subkey,revoke)
                cmd="sq__key__subkey__revoke"
                ;;
            sq__key__userid,add)
                cmd="sq__key__userid__add"
                ;;
            sq__key__userid,revoke)
                cmd="sq__key__userid__revoke"
                ;;
            sq__keyring,filter)
                cmd="sq__keyring__filter"
                ;;
            sq__keyring,list)
                cmd="sq__keyring__list"
                ;;
            sq__keyring,merge)
                cmd="sq__keyring__merge"
                ;;
            sq__keyring,split)
                cmd="sq__keyring__split"
                ;;
            sq__network,dane)
                cmd="sq__network__dane"
                ;;
            sq__network,keyserver)
                cmd="sq__network__keyserver"
                ;;
            sq__network,search)
                cmd="sq__network__search"
                ;;
            sq__network,wkd)
                cmd="sq__network__wkd"
                ;;
            sq__network__dane,generate)
                cmd="sq__network__dane__generate"
                ;;
            sq__network__dane,search)
                cmd="sq__network__dane__search"
                ;;
            sq__network__keyserver,publish)
                cmd="sq__network__keyserver__publish"
                ;;
            sq__network__keyserver,search)
                cmd="sq__network__keyserver__search"
                ;;
            sq__network__wkd,publish)
                cmd="sq__network__wkd__publish"
                ;;
            sq__network__wkd,search)
                cmd="sq__network__wkd__search"
                ;;
            sq__packet,armor)
                cmd="sq__packet__armor"
                ;;
            sq__packet,dearmor)
                cmd="sq__packet__dearmor"
                ;;
            sq__packet,decrypt)
                cmd="sq__packet__decrypt"
                ;;
            sq__packet,dump)
                cmd="sq__packet__dump"
                ;;
            sq__packet,join)
                cmd="sq__packet__join"
                ;;
            sq__packet,split)
                cmd="sq__packet__split"
                ;;
            sq__pki,authenticate)
                cmd="sq__pki__authenticate"
                ;;
            sq__pki,identify)
                cmd="sq__pki__identify"
                ;;
            sq__pki,link)
                cmd="sq__pki__link"
                ;;
            sq__pki,lookup)
                cmd="sq__pki__lookup"
                ;;
            sq__pki,path)
                cmd="sq__pki__path"
                ;;
            sq__pki,vouch)
                cmd="sq__pki__vouch"
                ;;
            sq__pki__link,add)
                cmd="sq__pki__link__add"
                ;;
            sq__pki__link,authorize)
                cmd="sq__pki__link__authorize"
                ;;
            sq__pki__link,list)
                cmd="sq__pki__link__list"
                ;;
            sq__pki__link,retract)
                cmd="sq__pki__link__retract"
                ;;
            sq__pki__vouch,add)
                cmd="sq__pki__vouch__add"
                ;;
            sq__pki__vouch,authorize)
                cmd="sq__pki__vouch__authorize"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        sq)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__cert)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help import export list lint"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__cert__export)
            opts="-v -q -h --output --local --all --cert --cert-userid --cert-email --cert-domain --cert-grep --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-grep)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__cert__import)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]..."
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__cert__lint)
            opts="-v -q -h --fix --cert --cert-userid --cert-email --cert-domain --cert-grep --cert-file --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-grep)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__cert__list)
            opts="-v -q -h --userid --email --show-paths --gossip --certification-network --amount --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [PATTERN]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --amount)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__config)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help get inspect template"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__config__get)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [NAME]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__config__inspect)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help paths network policy"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__config__inspect__network)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__config__inspect__paths)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__config__inspect__policy)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__config__template)
            opts="-v -q -h --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__decrypt)
            opts="-v -q -h --output --signatures --signer --signer-userid --signer-email --signer-domain --signer-file --recipient-file --dump-session-key --session-key --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signatures)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --recipient-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --session-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__download)
            opts="-v -q -h --url --signature --signer --signer-userid --signer-email --signer-domain --signer-file --signatures --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --url)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signature)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signatures)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__encrypt)
            opts="-v -q -h --output --binary --for --for-userid --for-email --for-file --for-self --with-password --with-password-file --set-metadata-filename --signer --signer-userid --signer-email --signer-file --signer-self --signature-notation --encrypt-for --compression --use-expired-subkey --profile --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --for)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --for-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --for-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --for-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --with-password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --set-metadata-filename)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signature-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --encrypt-for)
                    COMPREPLY=($(compgen -W "transport storage universal" -- "${cur}"))
                    return 0
                    ;;
                --compression)
                    COMPREPLY=($(compgen -W "none zip zlib bzip2" -- "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -W "rfc4880" -- "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help)
            opts="encrypt decrypt sign verify download inspect cert key pki network keyring packet config version help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__cert)
            opts="import export list lint"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__cert__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__cert__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__cert__lint)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__cert__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__config)
            opts="get inspect template"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__config__get)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__config__inspect)
            opts="paths network policy"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__config__inspect__network)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__config__inspect__paths)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__config__inspect__policy)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__config__template)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__decrypt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__download)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__encrypt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__inspect)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key)
            opts="list generate import export delete password expire revoke userid subkey approvals"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__approvals)
            opts="list update"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__approvals__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__approvals__update)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__expire)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__generate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__import)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__password)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__revoke)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__subkey)
            opts="add export delete password expire revoke bind"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__subkey__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__subkey__bind)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__subkey__delete)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__subkey__expire)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__subkey__export)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__subkey__password)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__subkey__revoke)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__userid)
            opts="add revoke"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__userid__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__key__userid__revoke)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__keyring)
            opts="list split merge filter"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__keyring__filter)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__keyring__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__keyring__merge)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__keyring__split)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__network)
            opts="search keyserver wkd dane"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__network__dane)
            opts="search generate"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__network__dane__generate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__network__dane__search)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__network__keyserver)
            opts="search publish"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__network__keyserver__publish)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__network__keyserver__search)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__network__search)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__network__wkd)
            opts="search publish"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__network__wkd__publish)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__network__wkd__search)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__packet)
            opts="armor dearmor dump decrypt split join"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__packet__armor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__packet__dearmor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__packet__decrypt)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__packet__dump)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__packet__join)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__packet__split)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__pki)
            opts="authenticate lookup identify vouch link path"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__pki__authenticate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__pki__identify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__pki__link)
            opts="add authorize retract list"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__pki__link__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__pki__link__authorize)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__pki__link__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__pki__link__retract)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__pki__lookup)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__pki__path)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__pki__vouch)
            opts="add authorize"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__pki__vouch__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__pki__vouch__authorize)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 5 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__sign)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__help__version)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__inspect)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-domain --cert-grep --cert-file --certifications --dump-bad-signatures --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-grep)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help list generate import export delete password expire revoke userid subkey approvals"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__approvals)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help list update"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__approvals__list)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --userid --email --name --pending --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__approvals__update)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --userid --email --name --remove-all --remove-by --add-all --add-by --add-authenticated --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --remove-by)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --add-by)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__delete)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__expire)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --output --expiration --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --expiration)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__export)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-domain --cert-grep --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-grep)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__generate)
            opts="-v -q -h --own-key --shared-key --name --email --userid --allow-non-canonical-userids --no-userids --cipher-suite --profile --new-password-file --without-password --can-sign --cannot-sign --can-authenticate --cannot-authenticate --can-encrypt --cannot-encrypt --output --rev-cert --expiration --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cipher-suite)
                    COMPREPLY=($(compgen -W "rsa2k rsa3k rsa4k cv25519" -- "${cur}"))
                    return 0
                    ;;
                --profile)
                    COMPREPLY=($(compgen -W "rfc4880" -- "${cur}"))
                    return 0
                    ;;
                --new-password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --can-encrypt)
                    COMPREPLY=($(compgen -W "transport storage universal" -- "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --rev-cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --expiration)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__import)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [KEY_FILE]..."
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__list)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-domain --cert-grep --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FINGERPRINT|KEYID|PATTERN]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-grep)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__password)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --new-password-file --clear-password --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --new-password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__revoke)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --revoker --revoker-userid --revoker-email --revoker-file --reason --message --signature-notation --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --revoker)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --revoker-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --revoker-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --revoker-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reason)
                    COMPREPLY=($(compgen -W "compromised superseded retired unspecified" -- "${cur}"))
                    return 0
                    ;;
                --message)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signature-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__subkey)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help add export delete password expire revoke bind"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__subkey__add)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --cipher-suite --expiration --can-sign --can-authenticate --can-encrypt --new-password-file --without-password --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cipher-suite)
                    COMPREPLY=($(compgen -W "rsa2k rsa3k rsa4k cv25519" -- "${cur}"))
                    return 0
                    ;;
                --expiration)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --can-encrypt)
                    COMPREPLY=($(compgen -W "transport storage universal" -- "${cur}"))
                    return 0
                    ;;
                --new-password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__subkey__bind)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --key --creation-time --expiration --allow-broken-crypto --can-sign --cannot-sign --can-authenticate --cannot-authenticate --can-encrypt --cannot-encrypt --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --creation-time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --expiration)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --can-encrypt)
                    COMPREPLY=($(compgen -W "transport storage universal" -- "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__subkey__delete)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --key --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__subkey__expire)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --key --output --expiration --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --expiration)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__subkey__export)
            opts="-v -q -h --cert --cert-userid --cert-email --key --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__subkey__password)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --key --new-password-file --clear-password --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --new-password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__subkey__revoke)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --revoker --revoker-userid --revoker-email --revoker-file --key --reason --message --signature-notation --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --revoker)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --revoker-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --revoker-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --revoker-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reason)
                    COMPREPLY=($(compgen -W "compromised superseded retired unspecified" -- "${cur}"))
                    return 0
                    ;;
                --message)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signature-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__userid)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help add revoke"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__userid__add)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --name --email --userid --allow-non-canonical-userids --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__key__userid__revoke)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --revoker --revoker-userid --revoker-email --revoker-file --userid --userid-or-add --email --email-or-add --name --name-or-add --allow-non-canonical-userids --reason --message --signature-notation --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --revoker)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --revoker-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --revoker-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --revoker-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --userid-or-add)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email-or-add)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --name-or-add)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --reason)
                    COMPREPLY=($(compgen -W "retired unspecified" -- "${cur}"))
                    return 0
                    ;;
                --message)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signature-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__keyring)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help list split merge filter"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__keyring__filter)
            opts="-v -q -h --experimental --output --userid --name --email --domain --cert --key --prune-certs --to-cert --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]..."
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__keyring__list)
            opts="-v -q -h --all-userids --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__keyring__merge)
            opts="-v -q -h --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]..."
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__keyring__split)
            opts="-v -q -h --prefix --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --prefix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__network)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help search keyserver wkd dane"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__network__dane)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help search generate"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__network__dane__generate)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --all --domain --ttl --size-limit --type --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ttl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --size-limit)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --type)
                    COMPREPLY=($(compgen -W "openpgp generic" -- "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__network__dane__search)
            opts="-v -q -h --all --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help <ADDRESS>..."
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__network__keyserver)
            opts="-v -q -h --server --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help search publish"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --server)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__network__keyserver__publish)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-domain --cert-file --server --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --server)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__network__keyserver__search)
            opts="-v -q -h --output --all --server --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help <QUERY>..."
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --server)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__network__search)
            opts="-v -q -h --server --output --all --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help <QUERY>..."
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --server)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__network__wkd)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help search publish"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__network__wkd__publish)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --all --create --method --rsync --rsync-path --domain --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help <DEST>"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --method)
                    COMPREPLY=($(compgen -W "advanced direct" -- "${cur}"))
                    return 0
                    ;;
                --rsync-path)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__network__wkd__search)
            opts="-v -q -h --all --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help <ADDRESS>..."
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__packet)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help armor dearmor dump decrypt split join"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__packet__armor)
            opts="-v -q -h --output --label --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --label)
                    COMPREPLY=($(compgen -W "auto message cert key sig file" -- "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__packet__dearmor)
            opts="-v -q -h --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__packet__decrypt)
            opts="-v -q -h --output --binary --recipient-file --session-key --dump-session-key --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --recipient-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --session-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__packet__dump)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-file --output --session-key --recipient-file --mpis --hex --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --session-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --recipient-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__packet__join)
            opts="-v -q -h --output --label --binary --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]..."
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --label)
                    COMPREPLY=($(compgen -W "auto message cert key sig file" -- "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__packet__split)
            opts="-v -q -h --output --binary --output-prefix --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output-prefix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__pki)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help authenticate lookup identify vouch link path"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__pki__authenticate)
            opts="-v -q -h --cert --userid --email --show-paths --gossip --certification-network --amount --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --amount)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__pki__identify)
            opts="-v -q -h --cert --show-paths --gossip --certification-network --amount --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --amount)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__pki__link)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help add authorize retract list"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__pki__link__add)
            opts="-v -q -h --cert --cert-special --all --userid --userid-or-add --email --email-or-add --allow-non-canonical-userids --amount --temporary --expiration --recreate --signature-notation --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-special)
                    COMPREPLY=($(compgen -W "public-directories keys.openpgp.org keys.mailvelope.com proton.me wkd dane autocrypt web" -- "${cur}"))
                    return 0
                    ;;
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --userid-or-add)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email-or-add)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --amount)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --expiration)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signature-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__pki__link__authorize)
            opts="-v -q -h --cert --cert-special --all --userid --userid-or-add --email --email-or-add --allow-non-canonical-userids --amount --depth --domain --regex --unconstrained --expiration --recreate --signature-notation --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-special)
                    COMPREPLY=($(compgen -W "public-directories keys.openpgp.org keys.mailvelope.com proton.me wkd dane autocrypt web" -- "${cur}"))
                    return 0
                    ;;
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --userid-or-add)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email-or-add)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --amount)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --depth)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --regex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --expiration)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signature-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__pki__link__list)
            opts="-v -q -h --cert --cert-userid --cert-email --cert-domain --cert-grep --ca --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [PATTERN]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-grep)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__pki__link__retract)
            opts="-v -q -h --signature-notation --recreate --cert --cert-special --all --userid --email --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --signature-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-special)
                    COMPREPLY=($(compgen -W "public-directories keys.openpgp.org keys.mailvelope.com proton.me wkd dane autocrypt web" -- "${cur}"))
                    return 0
                    ;;
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__pki__lookup)
            opts="-v -q -h --userid --email --show-paths --gossip --certification-network --amount --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --amount)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__pki__path)
            opts="-v -q -h --userid --email --name --certification-network --amount --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help <FINGERPRINT|KEYID>..."
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --amount)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__pki__vouch)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help add authorize"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__pki__vouch__add)
            opts="-v -q -h --certifier --certifier-userid --certifier-email --certifier-file --certifier-self --cert --cert-file --all --userid --userid-or-add --email --email-or-add --allow-non-canonical-userids --amount --expiration --local --non-revocable --signature-notation --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --certifier)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --certifier-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --certifier-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --certifier-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --userid-or-add)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email-or-add)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --amount)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --expiration)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signature-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__pki__vouch__authorize)
            opts="-v -q -h --certifier --certifier-userid --certifier-email --certifier-file --certifier-self --cert --cert-file --all --userid --userid-or-add --email --email-or-add --allow-non-canonical-userids --amount --depth --domain --regex --unconstrained --local --non-revocable --expiration --signature-notation --output --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --certifier)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --certifier-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --certifier-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --certifier-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --userid-or-add)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --email-or-add)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --amount)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --depth)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --regex)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --expiration)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signature-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__sign)
            opts="-v -q -h --output --binary --signature-file --message --cleartext --mode --append --notarize --merge --signer --signer-userid --signer-email --signer-file --signer-self --signature-notation --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signature-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "binary text" -- "${cur}"))
                    return 0
                    ;;
                --merge)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signature-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__verify)
            opts="-v -q -h --output --signature-file --message --cleartext --signatures --signer --signer-userid --signer-email --signer-domain --signer-file --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help [FILE]"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signature-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signatures)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-userid)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-email)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-domain)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --signer-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        sq__version)
            opts="-v -q -h --cli-version --overwrite --home --key-store --cert-store --keyring --known-notation --time --policy-as-of --trust-root --password-file --verbose --quiet --batch --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --cli-version)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --home)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --key-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cert-store)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keyring)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --known-notation)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --policy-as-of)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --trust-root)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --password-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _sq -o nosort -o bashdefault -o default sq
else
    complete -F _sq -o bashdefault -o default sq
fi
