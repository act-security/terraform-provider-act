package fakeapi

import (
	"context"
	"slices"

	"github.com/act-security/terraform-provider-act/internal/fakeapi/gen"
)

const eventHubNamespaceSuffix = ".servicebus.windows.net"

var (
	eventHubsCheck = credentialCheck{attribute: "eventsSubscriptionId", message: "Act could not read the Event Hubs"}
	eventHubNames  = map[gen.AzureLogStream]string{
		gen.AzureLogStreamActivityLogs: "act-activity-logs",
		gen.AzureLogStreamEntraIDLogs:  "act-entra-id-logs",
	}
)

func (f *Fake) AzureLogSource(deploymentID string) (gen.AzureLogSource, bool) {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	source, ok := f.deployments.azure.logSources[deploymentID]
	return source, ok
}

func (f *Fake) DeleteAzureLogSourceOutOfBand(deploymentID string) {
	f.deployments.mu.Lock()
	defer f.deployments.mu.Unlock()
	delete(f.deployments.azure.logSources, deploymentID)
}

func EventHubNamespace(eventsSubscriptionID string) string {
	return "act-logs-" + eventsSubscriptionID[:8] + eventHubNamespaceSuffix
}

func (s *apiServer) GetAzureLogSource(_ context.Context, req gen.GetAzureLogSourceRequestObject) (gen.GetAzureLogSourceResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	source, ok := store.azure.logSources[req.ID]
	if !ok {
		return gen.GetAzureLogSource404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	return gen.GetAzureLogSource200JSONResponse(source), nil
}

func (s *apiServer) PutAzureLogSource(_ context.Context, req gen.PutAzureLogSourceRequestObject) (gen.PutAzureLogSourceResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	deployment, ok := store.azure.byID[req.ID]
	if !ok {
		return gen.PutAzureLogSource404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	body := *req.Body
	if !body.ActivityLogs && !body.EntraIDLogs {
		return gen.PutAzureLogSource400JSONResponse(invalid("activityLogs", "no_stream")), nil
	}
	if deployment.item.Status != gen.DeploymentStatusActive {
		return gen.PutAzureLogSource409JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeConflict, "The deployment is "+string(deployment.item.Status))), nil
	}
	if failure, ok := store.nextFailure(body.EventsSubscriptionID); ok {
		return gen.PutAzureLogSource422JSONResponse(verificationFailed(eventHubsCheck, failure)), nil
	}
	source := gen.AzureLogSource{
		DeploymentID: req.ID,
		ActivityLogs: body.ActivityLogs,
		EntraIDLogs:  body.EntraIDLogs,
		EventHubs: streamHubs(streamUpdate{
			previous:  store.azure.logSources[req.ID].EventHubs,
			namespace: EventHubNamespace(body.EventsSubscriptionID),
			wanted:    map[gen.AzureLogStream]bool{gen.AzureLogStreamActivityLogs: body.ActivityLogs, gen.AzureLogStreamEntraIDLogs: body.EntraIDLogs},
		}),
	}
	store.azure.logSources[req.ID] = source
	return gen.PutAzureLogSource200JSONResponse(source), nil
}

func (s *apiServer) DeleteAzureLogSource(_ context.Context, req gen.DeleteAzureLogSourceRequestObject) (gen.DeleteAzureLogSourceResponseObject, error) {
	store := s.fake.deployments
	store.mu.Lock()
	defer store.mu.Unlock()
	source, ok := store.azure.logSources[req.ID]
	if !ok {
		return gen.DeleteAzureLogSource404JSONResponse(envelope(gen.ErrorEnvelopeErrorCodeNotFound, "Not found")), nil
	}
	delete(store.azure.logSources, req.ID)
	cleanup := []gen.CleanupItem{}
	for _, hub := range source.EventHubs {
		if hub.Enabled {
			cleanup = append(cleanup, gen.CleanupItem{
				Resource:    hub.Namespace + "/" + hub.EventHub,
				Description: "A diagnostic setting still streams " + string(hub.DataType) + " to this Event Hub. Remove it, or keep it to collect again later.",
			})
		}
	}
	return gen.DeleteAzureLogSource200JSONResponse{DeploymentID: req.ID, CleanupRequired: cleanup}, nil
}

type streamUpdate struct {
	previous  []gen.AzureLogSourceEventHub
	namespace string
	wanted    map[gen.AzureLogStream]bool
}

func streamHubs(update streamUpdate) []gen.AzureLogSourceEventHub {
	hubs := []gen.AzureLogSourceEventHub{}
	for _, stream := range []gen.AzureLogStream{gen.AzureLogStreamActivityLogs, gen.AzureLogStreamEntraIDLogs} {
		collected := slices.ContainsFunc(update.previous, func(hub gen.AzureLogSourceEventHub) bool { return hub.DataType == stream })
		if update.wanted[stream] || collected {
			hubs = append(hubs, gen.AzureLogSourceEventHub{Namespace: update.namespace, EventHub: eventHubNames[stream], DataType: stream, Enabled: update.wanted[stream]})
		}
	}
	return hubs
}
