package server

import (
	"encoding/json"
	"fmt"
	"github.com/aRestless/nexus/pkg/model"
	"github.com/go-chi/chi/v5"
	"gorm.io/gorm/clause"
	"net/http"
	"time"
)

func (s *Server) listLighthouses(w http.ResponseWriter, r *http.Request) {
	c := s.authenticateClient(r, false)
	if c == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	networkName := chi.URLParam(r, "network")
	var network model.Network
	res := s.db.First(&network, "name = ?", networkName)
	if res.RowsAffected != 1 {
		s.handleErr(fmt.Errorf("invalid network: %s", networkName), w)
		return
	}

	var clientNetwork model.ClientNetwork
	res = s.db.First(&clientNetwork, "network_id = ? AND client_id = ?", network.ID, c.ID)
	if res.RowsAffected != 1 {
		s.handleErr(fmt.Errorf("invalid client network %s for client %s", networkName, c.PublicKeyHash.String), w)
		return
	}

	var lighthouses []model.Lighthouse
	res = s.db.Find(&lighthouses,
		"network_id = ? AND updated_at > ?",
		network.ID,
		time.Now().Add(-4*time.Hour),
	)
	if res.Error != nil {
		s.handleErr(fmt.Errorf("finding lighthouses: %w", res.Error), w)
		return
	}

	resp := ListLighthousesResponse{}
	for _, l := range lighthouses {

		resp.Items = append(resp.Items, Lighthouse{
			PublicAddr: l.PublicAddr.ToNetip(),
			NebulaIP:   l.NebulaIP.ToNetip(),
		})
	}

	b, err := json.Marshal(&resp)
	if err != nil {
		s.handleErr(fmt.Errorf("marshalling response : %w", err), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(b)
	if err != nil {
		s.handleErr(fmt.Errorf("flushing response : %w", err), w)
		return
	}
}

func (s *Server) createLighthouse(w http.ResponseWriter, r *http.Request) {
	c := s.authenticateClient(r, false)
	if c == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	networkName := chi.URLParam(r, "network")

	network := model.Network{}
	res := s.db.Preload(clause.Associations).Find(&network, "name = ?", networkName)
	if res.RowsAffected == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	var clientNetwork model.ClientNetwork
	res = s.db.First(&clientNetwork, "network_id = ? AND client_id = ?", network.ID, c.ID)
	if res.RowsAffected != 1 {
		s.handleErr(fmt.Errorf("invalid client network %s for client %s", networkName, c.PublicKeyHash.String), w)
		return
	}

	if !clientNetwork.IsLighthouse {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	req := CreateLighthouseRequest{}
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		s.handleErr(err, w)
		return
	}

	var lighthouse model.Lighthouse
	s.db.First(&lighthouse, "network_id = ? AND nebula_ip = ?", network.ID, clientNetwork.Address)

	lighthouse.NetworkID = network.ID
	lighthouse.PublicAddr = model.AddrPort(req.PublicAddr)
	lighthouse.NebulaIP = clientNetwork.Address
	res = s.db.Save(&lighthouse)

	if res.Error != nil {
		s.handleErr(err, w)
		return
	}

	resp := CreateLighthouseResponse{
		PublicAddr: req.PublicAddr,
		NebulaIP:   clientNetwork.Address.ToNetip(),
	}

	b, err := json.Marshal(&resp)
	if err != nil {
		s.handleErr(fmt.Errorf("marshalling response : %w", err), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(b)
	if err != nil {
		s.handleErr(fmt.Errorf("flushing response : %w", err), w)
		return
	}
}
