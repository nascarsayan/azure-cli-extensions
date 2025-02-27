# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
#
# Code generated by aaz-dev-tools
# --------------------------------------------------------------------------------------------

# pylint: skip-file
# flake8: noqa

from azure.cli.core.aaz import *


@register_command(
    "apic service portal default create",
)
class Create(AAZCommand):
    """Create new or updates existing portal configuration.

    :example: Create Default Portal Configuration
        az apic service portal default create -g contoso-resources --service-name contoso --title "Contoso" --enabled false  --authentication'{"clientId":"00000000-0000-0000-0000-000000000000","tenantId":"00000000-0000-0000-0000-000000000000"}'
    """

    _aaz_info = {
        "version": "2024-03-01",
        "resources": [
            ["mgmt-plane", "/subscriptions/{}/resourcegroups/{}/providers/microsoft.apicenter/services/{}/portals/default", "2024-03-01"],
        ]
    }

    def _handler(self, command_args):
        super()._handler(command_args)
        self._execute_operations()
        return self._output()

    _args_schema = None

    @classmethod
    def _build_arguments_schema(cls, *args, **kwargs):
        if cls._args_schema is not None:
            return cls._args_schema
        cls._args_schema = super()._build_arguments_schema(*args, **kwargs)

        # define Arg Group ""

        _args_schema = cls._args_schema
        _args_schema.resource_group = AAZResourceGroupNameArg(
            required=True,
        )
        _args_schema.service_name = AAZStrArg(
            options=["-s", "--service", "--service-name"],
            help="The name of Azure API Center service.",
            required=True,
            fmt=AAZStrArgFormat(
                max_length=90,
                min_length=1,
            ),
        )

        # define Arg Group "Payload"

        _args_schema = cls._args_schema
        _args_schema.location = AAZResourceLocationArg(
            arg_group="Payload",
            help="The geo-location where the resource lives",
            required=True,
            fmt=AAZResourceLocationArgFormat(
                resource_group_arg="resource_group",
            ),
        )
        _args_schema.tags = AAZDictArg(
            options=["--tags"],
            arg_group="Payload",
            help="Resource tags.",
        )

        tags = cls._args_schema.tags
        tags.Element = AAZStrArg()

        # define Arg Group "Properties"

        _args_schema = cls._args_schema
        _args_schema.authentication = AAZObjectArg(
            options=["--authentication"],
            arg_group="Properties",
            help="Authentication configuration.",
        )
        _args_schema.enabled = AAZBoolArg(
            options=["--enabled"],
            arg_group="Properties",
            help="Flag indicating whether or not portal is enabled.",
        )
        _args_schema.title = AAZStrArg(
            options=["--title"],
            arg_group="Properties",
            help="Portal configuration Title.",
            fmt=AAZStrArgFormat(
                max_length=50,
            ),
        )

        authentication = cls._args_schema.authentication
        authentication.client_id = AAZStrArg(
            options=["client-id"],
            help="The Azure Active Directory application client id.",
            required=True,
            fmt=AAZStrArgFormat(
                max_length=50,
                min_length=1,
            ),
        )
        authentication.tenant_id = AAZStrArg(
            options=["tenant-id"],
            help="The Azure Active Directory application Tenant id.",
            fmt=AAZStrArgFormat(
                max_length=50,
            ),
        )
        return cls._args_schema

    def _execute_operations(self):
        self.pre_operations()
        self.PortalConfigurationCreateOrUpdate(ctx=self.ctx)()
        self.post_operations()

    @register_callback
    def pre_operations(self):
        pass

    @register_callback
    def post_operations(self):
        pass

    def _output(self, *args, **kwargs):
        result = self.deserialize_output(self.ctx.vars.instance, client_flatten=True)
        return result

    class PortalConfigurationCreateOrUpdate(AAZHttpOperation):
        CLIENT_TYPE = "MgmtClient"

        def __call__(self, *args, **kwargs):
            request = self.make_request()
            session = self.client.send_request(request=request, stream=False, **kwargs)
            if session.http_response.status_code in [200]:
                return self.on_200(session)

            return self.on_error(session.http_response)

        @property
        def url(self):
            return self.client.format_url(
                "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ApiCenter/services/{serviceName}/portals/default",
                **self.url_parameters
            )

        @property
        def method(self):
            return "PUT"

        @property
        def error_format(self):
            return "MgmtErrorFormat"

        @property
        def url_parameters(self):
            parameters = {
                **self.serialize_url_param(
                    "resourceGroupName", self.ctx.args.resource_group,
                    required=True,
                ),
                **self.serialize_url_param(
                    "serviceName", self.ctx.args.service_name,
                    required=True,
                ),
                **self.serialize_url_param(
                    "subscriptionId", self.ctx.subscription_id,
                    required=True,
                ),
            }
            return parameters

        @property
        def query_parameters(self):
            parameters = {
                **self.serialize_query_param(
                    "api-version", "2024-03-01",
                    required=True,
                ),
            }
            return parameters

        @property
        def header_parameters(self):
            parameters = {
                **self.serialize_header_param(
                    "Content-Type", "application/json",
                ),
                **self.serialize_header_param(
                    "Accept", "application/json",
                ),
            }
            return parameters

        @property
        def content(self):
            _content_value, _builder = self.new_content_builder(
                self.ctx.args,
                typ=AAZObjectType,
                typ_kwargs={"flags": {"required": True, "client_flatten": True}}
            )
            _builder.set_prop("location", AAZStrType, ".location", typ_kwargs={"flags": {"required": True}})
            _builder.set_prop("properties", AAZObjectType, typ_kwargs={"flags": {"client_flatten": True}})
            _builder.set_prop("tags", AAZDictType, ".tags")

            properties = _builder.get(".properties")
            if properties is not None:
                properties.set_prop("authentication", AAZObjectType, ".authentication", typ_kwargs={"flags": {"required": True}})
                properties.set_prop("enabled", AAZBoolType, ".enabled")
                properties.set_prop("title", AAZStrType, ".title", typ_kwargs={"flags": {"required": True}})

            authentication = _builder.get(".properties.authentication")
            if authentication is not None:
                authentication.set_prop("clientId", AAZStrType, ".client_id", typ_kwargs={"flags": {"required": True}})
                authentication.set_prop("tenantId", AAZStrType, ".tenant_id")

            tags = _builder.get(".tags")
            if tags is not None:
                tags.set_elements(AAZStrType, ".")

            return self.serialize_content(_content_value)

        def on_200(self, session):
            data = self.deserialize_http_content(session)
            self.ctx.set_var(
                "instance",
                data,
                schema_builder=self._build_schema_on_200
            )

        _schema_on_200 = None

        @classmethod
        def _build_schema_on_200(cls):
            if cls._schema_on_200 is not None:
                return cls._schema_on_200

            cls._schema_on_200 = AAZObjectType()

            _schema_on_200 = cls._schema_on_200
            _schema_on_200.id = AAZStrType(
                flags={"read_only": True},
            )
            _schema_on_200.name = AAZStrType(
                flags={"read_only": True},
            )
            _schema_on_200.properties = AAZObjectType(
                flags={"client_flatten": True},
            )
            _schema_on_200.system_data = AAZObjectType(
                serialized_name="systemData",
                flags={"read_only": True},
            )
            _schema_on_200.type = AAZStrType(
                flags={"read_only": True},
            )

            properties = cls._schema_on_200.properties
            properties.authentication = AAZObjectType()
            properties.created = AAZStrType()
            properties.created_by = AAZStrType(
                serialized_name="createdBy",
            )
            properties.data_api_host_name = AAZStrType(
                serialized_name="dataApiHostName",
            )
            properties.enabled = AAZBoolType()
            properties.portal_default_host_name = AAZStrType(
                serialized_name="portalDefaultHostName",
            )
            properties.title = AAZStrType()
            properties.updated = AAZStrType()
            properties.updated_by = AAZStrType(
                serialized_name="updatedBy",
            )

            authentication = cls._schema_on_200.properties.authentication
            authentication.azure_ad_instance = AAZStrType(
                serialized_name="azureAdInstance",
                flags={"read_only": True},
            )
            authentication.client_id = AAZStrType(
                serialized_name="clientId",
                flags={"required": True},
            )
            authentication.scopes = AAZStrType(
                flags={"read_only": True},
            )
            authentication.tenant_id = AAZStrType(
                serialized_name="tenantId",
            )

            system_data = cls._schema_on_200.system_data
            system_data.created_at = AAZStrType(
                serialized_name="createdAt",
            )
            system_data.created_by = AAZStrType(
                serialized_name="createdBy",
            )
            system_data.created_by_type = AAZStrType(
                serialized_name="createdByType",
            )
            system_data.last_modified_at = AAZStrType(
                serialized_name="lastModifiedAt",
            )
            system_data.last_modified_by = AAZStrType(
                serialized_name="lastModifiedBy",
            )
            system_data.last_modified_by_type = AAZStrType(
                serialized_name="lastModifiedByType",
            )

            return cls._schema_on_200


class _CreateHelper:
    """Helper class for Create"""


__all__ = ["Create"]
