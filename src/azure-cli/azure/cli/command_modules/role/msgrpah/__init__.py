# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------


"""
A light-weight Microsoft Graph client, similar to https://github.com/microsoftgraph/msgraph-sdk-python-core
"""

from ._graph_client import GraphClient, GraphError

__all__ = [
    "GraphClient",
    "GraphError"
]
